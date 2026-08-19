/**
 * @file test_guard_sse_common.cpp
 * @brief Unit tests for Guard::Sse -- the shared SSE frame machinery
 *        (src/guard/sse/Common.hpp).
 *
 * `ClassifyFrame` and `JSONCloseTracker` port every case from the Go
 * reference's own test files exhaustively:
 *   - `internal/sseproc/common/eventframe_test.go`: `TestClassifyFrame`
 *     (5 subtests: canonical data-with-space, data-without-space,
 *     done-with-space, done-without-space, comment passthrough,
 *     multi-line join -- 6 total, see the ClassifyFrame section below).
 *   - `internal/sseproc/common/json_depth_test.go`: `TestJSONCloseTracker`
 *     (6 subtests: complete-in-one-fragment, empty object, split-across-
 *     fragments, in-string-brace-does-not-close-early, escaped-quote-keeps-
 *     string-open, nested-objects) and
 *     `TestJSONCloseTracker_NoSpuriousCloseWithoutOpen`.
 *
 * `SplitFrames`, `BuildEventFrame` and `MaskedTextRecorder` have NO
 * dedicated Go test file (grep confirms `frame_test.go` and
 * `masked_response_test.go` don't exist in the reference tree; `SplitFrames`
 * and `BuildEventFrame` are only exercised indirectly through the dialect
 * processors' 800-3800 line corpora, out of this task's scope). This file
 * writes its own thorough coverage for them instead, straight from the
 * documented Go semantics (frame.go's doc comments, eventframe.go's
 * `DataPrefix`, masked_response.go's doc comments) rather than a ported
 * table.
 */

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "guard/sse/Common.hpp"

namespace {

using Guard::Sse::build_event_frame;
using Guard::Sse::ClassifiedFrame;
using Guard::Sse::classify_frame;
using Guard::Sse::FrameKind;
using Guard::Sse::FrameSplit;
using Guard::Sse::JsonCloseTracker;
using Guard::Sse::MaskedTextRecorder;
using Guard::Sse::split_frames;

std::vector<std::string> as_strings(const std::vector<std::string_view>& views) {
    std::vector<std::string> out;
    out.reserve(views.size());
    for (std::string_view v : views)
        out.emplace_back(v);
    return out;
}

// ---------------------------------------------------------------------------
// split_frames -- no dedicated Go test file; own coverage of the documented
// SplitFrames/FindFrameSeparator semantics (frame.go).
// ---------------------------------------------------------------------------

TEST(GuardSseSplitFrames, EmptyBufferYieldsNoFramesAndEmptyTail) {
    const FrameSplit result = split_frames("");
    EXPECT_TRUE(result.frames.empty());
    EXPECT_TRUE(result.tail.empty());
}

TEST(GuardSseSplitFrames, SingleLfTerminatedFrame) {
    const FrameSplit result = split_frames("data: a\n\n");
    ASSERT_EQ(result.frames.size(), 1U);
    EXPECT_EQ(result.frames[0], "data: a\n\n");
    EXPECT_TRUE(result.tail.empty());
}

TEST(GuardSseSplitFrames, SingleCrlfTerminatedFrame) {
    const FrameSplit result = split_frames("data: a\r\n\r\n");
    ASSERT_EQ(result.frames.size(), 1U);
    EXPECT_EQ(result.frames[0], "data: a\r\n\r\n");
    EXPECT_TRUE(result.tail.empty());
}

TEST(GuardSseSplitFrames, MultipleLfFramesInOneBuffer) {
    const FrameSplit result = split_frames("data: a\n\ndata: b\n\ndata: c\n\n");
    ASSERT_EQ(result.frames.size(), 3U);
    EXPECT_EQ(result.frames[0], "data: a\n\n");
    EXPECT_EQ(result.frames[1], "data: b\n\n");
    EXPECT_EQ(result.frames[2], "data: c\n\n");
    EXPECT_TRUE(result.tail.empty());
}

TEST(GuardSseSplitFrames, MixedLfAndCrlfSeparatorsInOneBuffer) {
    const FrameSplit result = split_frames("data: a\n\ndata: b\r\n\r\ndata: c\n\n");
    ASSERT_EQ(result.frames.size(), 3U);
    EXPECT_EQ(result.frames[0], "data: a\n\n");
    EXPECT_EQ(result.frames[1], "data: b\r\n\r\n");
    EXPECT_EQ(result.frames[2], "data: c\n\n");
}

TEST(GuardSseSplitFrames, UnterminatedFinalFrameCarriesIntoTail) {
    const FrameSplit result = split_frames("data: a\n\ndata: b");
    ASSERT_EQ(result.frames.size(), 1U);
    EXPECT_EQ(result.frames[0], "data: a\n\n");
    EXPECT_EQ(result.tail, "data: b");
}

TEST(GuardSseSplitFrames, NoSeparatorAtAllIsEntirelyTail) {
    const FrameSplit result = split_frames("data: incomplete, no terminator");
    EXPECT_TRUE(result.frames.empty());
    EXPECT_EQ(result.tail, "data: incomplete, no terminator");
}

TEST(GuardSseSplitFrames, BareSeparatorAloneIsOneEmptyFrame) {
    const FrameSplit result = split_frames("\n\n");
    ASSERT_EQ(result.frames.size(), 1U);
    EXPECT_EQ(result.frames[0], "\n\n");
    EXPECT_TRUE(result.tail.empty());
}

TEST(GuardSseSplitFrames, CrlfPreferredWhenItStartsEarlierThanLf) {
    // FindFrameSeparator picks the EARLIER match; here CRLF starts before the
    // "\n\n" that would otherwise be found later in the buffer.
    const FrameSplit result = split_frames("a\r\n\r\nb\n\nc");
    ASSERT_EQ(result.frames.size(), 2U);
    EXPECT_EQ(result.frames[0], "a\r\n\r\n");
    EXPECT_EQ(result.frames[1], "b\n\n");
    EXPECT_EQ(result.tail, "c");
}

TEST(GuardSseSplitFrames, LfPreferredWhenItStartsEarlierThanCrlf) {
    const FrameSplit result = split_frames("a\n\nb\r\n\r\nc");
    ASSERT_EQ(result.frames.size(), 2U);
    EXPECT_EQ(result.frames[0], "a\n\n");
    EXPECT_EQ(result.frames[1], "b\r\n\r\n");
    EXPECT_EQ(result.tail, "c");
}

TEST(GuardSseSplitFrames, TailIsEmptyStringViewNotJustEmpty) {
    // Distinguish "no leftover bytes" (this case) from "leftover bytes that
    // happen to be empty" -- both compare equal as string_view, but this
    // pins that a fully-consumed buffer takes the loop-exit path, not the
    // no-separator-found early return.
    const FrameSplit result = split_frames("data: a\n\n");
    EXPECT_EQ(result.tail.size(), 0U);
}

// Boundary-fragmentation: feed the same logical stream split at every
// possible byte offset (as a caller streaming one byte at a time from the
// network would), carrying `tail` forward as the next call's prefix exactly
// as the SSE processors do. The reassembled frame sequence must be
// independent of where the chunk boundaries fall.
TEST(GuardSseSplitFrames, ReassemblyIsIndependentOfChunkBoundaries) {
    const std::string whole = "event: a\ndata: 1\n\nevent: b\ndata: 2\r\n\r\nevent: c\ndata: 3\n\n";
    const std::vector<std::string> want = {
        "event: a\ndata: 1\n\n",
        "event: b\ndata: 2\r\n\r\n",
        "event: c\ndata: 3\n\n",
    };

    for (std::size_t chunk_size = 1; chunk_size <= whole.size() + 1; ++chunk_size) {
        std::string pending;
        std::vector<std::string> frames;
        for (std::size_t i = 0; i < whole.size(); i += chunk_size) {
            const std::string chunk = pending + whole.substr(i, chunk_size);
            const FrameSplit split = split_frames(chunk);
            for (std::string_view f : split.frames)
                frames.emplace_back(f);
            pending.assign(split.tail);
        }
        EXPECT_TRUE(pending.empty()) << "chunk_size=" << chunk_size;
        EXPECT_EQ(frames, want) << "chunk_size=" << chunk_size;
    }
}

TEST(GuardSseSplitFrames, SeparatorSplitExactlyAcrossTwoChunks) {
    // The "\n\n" separator itself straddles the chunk boundary: first chunk
    // ends right after a single '\n', second chunk starts with the second.
    FrameSplit first = split_frames("data: a\n");
    EXPECT_TRUE(first.frames.empty());
    EXPECT_EQ(first.tail, "data: a\n");

    const std::string next = std::string(first.tail) + "\ndata: b\n\n";
    FrameSplit second = split_frames(next);
    ASSERT_EQ(second.frames.size(), 2U);
    EXPECT_EQ(second.frames[0], "data: a\n\n");
    EXPECT_EQ(second.frames[1], "data: b\n\n");
    EXPECT_TRUE(second.tail.empty());
}

TEST(GuardSseSplitFrames, CrlfSeparatorSplitAcrossMultipleChunks) {
    // "\r\n\r\n" split after each byte in turn. `first_chunk` is a NAMED local
    // (not a temporary passed directly to split_frames): FrameSplit's
    // `frames`/`tail` are string_views into whatever buffer was passed in, so
    // they must not outlive that buffer -- binding the substring to a
    // variable that spans the rest of the loop body keeps them valid for as
    // long as this iteration reads them.
    const std::string whole = "data: a\r\n\r\ndata: b\r\n\r\n";
    for (std::size_t split_at = 1; split_at < whole.size(); ++split_at) {
        const std::string first_chunk = whole.substr(0, split_at);
        FrameSplit first = split_frames(first_chunk);
        std::vector<std::string> frames = as_strings(first.frames);
        const std::string combined = std::string(first.tail) + whole.substr(split_at);
        FrameSplit second = split_frames(combined);
        for (std::string_view f : second.frames)
            frames.emplace_back(f);
        EXPECT_EQ(frames, (std::vector<std::string>{"data: a\r\n\r\n", "data: b\r\n\r\n"})) << "split_at=" << split_at;
        EXPECT_TRUE(second.tail.empty()) << "split_at=" << split_at;
    }
}

// ---------------------------------------------------------------------------
// classify_frame -- ports eventframe_test.go's TestClassifyFrame exhaustively.
// ---------------------------------------------------------------------------

struct ClassifyCase {
    std::string name;
    std::string frame;
    FrameKind want_kind;
    std::string want_payload;
};

class GuardSseClassifyFrame : public ::testing::TestWithParam<ClassifyCase> {};

TEST_P(GuardSseClassifyFrame, MatchesGoTestClassifyFrame) {
    const ClassifyCase& tc = GetParam();
    const ClassifiedFrame result = classify_frame(tc.frame);
    EXPECT_EQ(result.kind, tc.want_kind) << tc.name;
    if (tc.want_kind == FrameKind::Event) {
        EXPECT_EQ(result.data, tc.want_payload) << tc.name;
    }
    EXPECT_EQ(result.raw, tc.frame) << tc.name;
}

INSTANTIATE_TEST_SUITE_P(
    PortedFromGo,
    GuardSseClassifyFrame,
    ::testing::Values(
        // "canonical data line with space"
        ClassifyCase{"canonical data line with space", "event: x\ndata: {\"a\":1}\n\n", FrameKind::Event, R"({"a":1})"},
        // "data line without space" -- SSE-legal, no space after "data:"
        ClassifyCase{"data line without space", "event: x\ndata:{\"a\":1}\n\n", FrameKind::Event, R"({"a":1})"},
        // "done sentinel with space"
        ClassifyCase{"done sentinel with space", "data: [DONE]\n\n", FrameKind::Done, ""},
        // "done sentinel without space"
        ClassifyCase{"done sentinel without space", "data:[DONE]\n\n", FrameKind::Done, ""},
        // "comment line passes through"
        ClassifyCase{"comment line passes through", ": keep-alive\n\n", FrameKind::Passthrough, ""},
        // "multi-line data joined with newline"
        ClassifyCase{"multi-line data joined with newline",
                     "event: x\ndata: line1\ndata: line2\n\n",
                     FrameKind::Event,
                     "line1\nline2"}),
    [](const ::testing::TestParamInfo<ClassifyCase>& param_info) { return std::to_string(param_info.index); });

// Additional edge cases beyond the ported table, covering the file-level
// notes on the len()>0 (not nil) gate and event:/id:/retry:/CRLF handling.

TEST(GuardSseClassifyFrameExtra, SingleEmptyDataLineIsPassthroughNotEvent) {
    // Go: dataPayload becomes a non-nil EMPTY slice; the final classification
    // gate is `len(dataPayload) > 0`, which is false here.
    const ClassifiedFrame result = classify_frame("data:\n\n");
    EXPECT_EQ(result.kind, FrameKind::Passthrough);
}

TEST(GuardSseClassifyFrameExtra, TwoEmptyDataLinesJoinToASingleNewline) {
    // The joining '\n' alone makes the accumulated payload non-empty, so
    // THIS classifies as Event with data == "\n".
    const ClassifiedFrame result = classify_frame("data:\ndata:\n\n");
    EXPECT_EQ(result.kind, FrameKind::Event);
    EXPECT_EQ(result.data, "\n");
}

TEST(GuardSseClassifyFrameExtra, IdAndRetryLinesAreIgnoredForClassification) {
    const ClassifiedFrame result = classify_frame("id: 42\nretry: 3000\nevent: x\ndata: payload\n\n");
    EXPECT_EQ(result.kind, FrameKind::Event);
    EXPECT_EQ(result.data, "payload");
}

TEST(GuardSseClassifyFrameExtra, FrameWithOnlyIdAndRetryLinesIsPassthrough) {
    const ClassifiedFrame result = classify_frame("id: 42\nretry: 3000\n\n");
    EXPECT_EQ(result.kind, FrameKind::Passthrough);
}

TEST(GuardSseClassifyFrameExtra, EmptyFrameIsPassthrough) {
    const ClassifiedFrame result = classify_frame("");
    EXPECT_EQ(result.kind, FrameKind::Passthrough);
    EXPECT_TRUE(result.data.empty());
}

TEST(GuardSseClassifyFrameExtra, CrlfLineEndingsAreSupported) {
    const ClassifiedFrame result = classify_frame("event: x\r\ndata: payload\r\n\r\n");
    EXPECT_EQ(result.kind, FrameKind::Event);
    EXPECT_EQ(result.data, "payload");
}

TEST(GuardSseClassifyFrameExtra, CrlfMultiLineDataJoinsWithBareNewlineNotCrlf) {
    // Each line's trailing \r is trimmed before joining, so the join
    // separator is a bare '\n' even for a CRLF-terminated frame.
    const ClassifiedFrame result = classify_frame("event: x\r\ndata: line1\r\ndata: line2\r\n\r\n");
    EXPECT_EQ(result.kind, FrameKind::Event);
    EXPECT_EQ(result.data, "line1\nline2");
}

TEST(GuardSseClassifyFrameExtra, DoneAfterAccumulatedDataDiscardsIt) {
    // A [DONE] data: line short-circuits immediately, regardless of what was
    // already joined from earlier data: lines in the same frame.
    const ClassifiedFrame result = classify_frame("data: partial\ndata: [DONE]\n\n");
    EXPECT_EQ(result.kind, FrameKind::Done);
}

TEST(GuardSseClassifyFrameExtra, DoneSentinelSurroundedByOtherWhitespaceIsNotDone) {
    // The comparison is byte-exact equality against "[DONE]" after stripping
    // ONE optional leading space -- extra internal whitespace does not match.
    const ClassifiedFrame result = classify_frame("data: [ DONE ]\n\n");
    EXPECT_EQ(result.kind, FrameKind::Event);
    EXPECT_EQ(result.data, "[ DONE ]");
}

TEST(GuardSseClassifyFrameExtra, RawIsAlwaysTheVerbatimInputRegardlessOfKind) {
    const std::string frame = "event: x\ndata: {\"a\":1}\n\n";
    EXPECT_EQ(classify_frame(frame).raw, frame);
    const std::string done_frame = "data: [DONE]\n\n";
    EXPECT_EQ(classify_frame(done_frame).raw, done_frame);
    const std::string comment_frame = ": ping\n\n";
    EXPECT_EQ(classify_frame(comment_frame).raw, comment_frame);
}

// ---------------------------------------------------------------------------
// build_event_frame -- no dedicated Go test; own coverage of the documented
// "data: " + data + "\n\n" format (eventframe.go's DataPrefix).
// ---------------------------------------------------------------------------

TEST(GuardSseBuildEventFrame, ExactByteFormat) {
    EXPECT_EQ(build_event_frame(R"({"a":1})"), "data: {\"a\":1}\n\n");
}

TEST(GuardSseBuildEventFrame, EmptyPayloadStillEmitsPrefixAndTerminator) {
    EXPECT_EQ(build_event_frame(""), "data: \n\n");
}

TEST(GuardSseBuildEventFrame, RoundTripsThroughClassifyFrame) {
    const std::string payload = R"({"type":"content_block_delta"})";
    const std::string frame = build_event_frame(payload);
    const ClassifiedFrame parsed = classify_frame(frame);
    EXPECT_EQ(parsed.kind, FrameKind::Event);
    EXPECT_EQ(parsed.data, payload);
}

TEST(GuardSseBuildEventFrame, DoneSentinelRoundTrips) {
    const std::string frame = build_event_frame("[DONE]");
    EXPECT_EQ(frame, "data: [DONE]\n\n");
    EXPECT_EQ(classify_frame(frame).kind, FrameKind::Done);
}

// ---------------------------------------------------------------------------
// JsonCloseTracker -- ports json_depth_test.go's TestJSONCloseTracker
// exhaustively, plus its NoSpuriousCloseWithoutOpen test and this port's own
// 1-byte-at-a-time torture matrix (the JsonCloseTracker docstring flags this
// as security-relevant: under-detecting a close would leave a tool-call
// demasker un-flushed, over-detecting would flush early and split a
// placeholder across the boundary).
// ---------------------------------------------------------------------------

/// Feeds `fragments` in order into a fresh tracker and returns the index of
/// the fragment at which `closed()` FIRST flips true, or -1 if it never
/// does. Mirrors Go's `feedAll` helper (json_depth_test.go:7-16), adapted to
/// this port's sticky closed() contract (see Common.hpp's file-level note).
int feed_all(const std::vector<std::string>& fragments) {
    JsonCloseTracker tracker;
    for (std::size_t i = 0; i < fragments.size(); ++i) {
        tracker.feed(fragments[i]);
        if (tracker.closed())
            return static_cast<int>(i);
    }
    return -1;
}

struct JsonCloseCase {
    std::string name;
    std::vector<std::string> fragments;
    int want_close;
};

class GuardSseJsonCloseTracker : public ::testing::TestWithParam<JsonCloseCase> {};

TEST_P(GuardSseJsonCloseTracker, MatchesGoTestJSONCloseTracker) {
    const JsonCloseCase& tc = GetParam();
    EXPECT_EQ(feed_all(tc.fragments), tc.want_close) << tc.name;
}

INSTANTIATE_TEST_SUITE_P(
    PortedFromGo,
    GuardSseJsonCloseTracker,
    ::testing::Values(JsonCloseCase{"complete object in one fragment", {R"({"x":"y"})"}, 0},
                      JsonCloseCase{"empty object", {"{}"}, 0},
                      JsonCloseCase{"split across fragments", {R"({"city":)", R"("Paris")", "}"}, 2},
                      JsonCloseCase{
                          "in-string brace does not close early", {R"({"note":"start)", "end } more", R"("})"}, 2},
                      JsonCloseCase{"escaped quote keeps string open", {"{\"k\":\"a\\", "\" }", "\"}"}, 2},
                      JsonCloseCase{"nested objects", {R"({"a":{"b":1})", R"(,"c":2})"}, 1}),
    [](const ::testing::TestParamInfo<JsonCloseCase>& param_info) { return std::to_string(param_info.index); });

TEST(GuardSseJsonCloseTrackerExtra, NoSpuriousCloseWithoutOpen) {
    JsonCloseTracker tracker;
    tracker.feed("}");
    EXPECT_FALSE(tracker.closed());
}

TEST(GuardSseJsonCloseTrackerExtra, ResetReturnsToFreshState) {
    JsonCloseTracker tracker;
    tracker.feed(R"({"a":1})");
    ASSERT_TRUE(tracker.closed());

    tracker.reset();
    EXPECT_FALSE(tracker.closed());

    // Fully usable for a second object after reset.
    tracker.feed(R"({"b":2})");
    EXPECT_TRUE(tracker.closed());
}

TEST(GuardSseJsonCloseTrackerExtra, ClosedStaysStickyAcrossFurtherFeedsUntilReset) {
    JsonCloseTracker tracker;
    tracker.feed(R"({"a":1})");
    ASSERT_TRUE(tracker.closed());
    tracker.feed("");  // further no-op feeds must not un-close it
    EXPECT_TRUE(tracker.closed());
}

TEST(GuardSseJsonCloseTrackerExtra, DefaultConstructedTrackerStartsUnclosed) {
    JsonCloseTracker tracker;
    EXPECT_FALSE(tracker.closed());
}

// Torture matrix: every case from the ported table above, fed ONE BYTE AT A
// TIME (the worst-case fragmentation a real network stream can produce),
// must still report the close at the correct overall byte offset, and must
// never report a close early.
TEST(GuardSseJsonCloseTrackerTorture, OneByteAtATimeMatchesWholeFragmentResult) {
    const std::vector<std::pair<std::string, std::size_t>> cases = {
        {R"({"x":"y"})", 8},                     // closes at the final '}'
        {"{}", 1},                               // closes at the final '}'
        {R"({"city":"Paris"})", 15},             // closes at the final '}'
        {R"({"note":"start end } more"})", 26},  // in-string '}' at offset 19 must NOT close early
        {"{\"k\":\"a\\\" }\"}", 12},             // escaped quote keeps string open through the space
        {R"({"a":{"b":1},"c":2})", 18},          // inner close (offset 11) must not close the top level
    };

    for (const auto& [json, want_close_byte] : cases) {
        JsonCloseTracker tracker;
        bool closed_at_least_once = false;
        std::size_t closed_byte = 0;
        for (std::size_t i = 0; i < json.size(); ++i) {
            const bool was_closed = tracker.closed();
            tracker.feed(json.substr(i, 1));
            if (!was_closed && tracker.closed() && !closed_at_least_once) {
                closed_at_least_once = true;
                closed_byte = i;
            }
        }
        ASSERT_TRUE(closed_at_least_once) << json;
        EXPECT_EQ(closed_byte, want_close_byte) << json;
    }
}

TEST(GuardSseJsonCloseTrackerTorture, DeeplyNestedObjectsAndArraysOneByteAtATime) {
    const std::string json = R"({"a":[{"b":{"c":[1,2,{"d":"e"}]}},{"f":"g"}]})";
    JsonCloseTracker tracker;
    for (std::size_t i = 0; i + 1 < json.size(); ++i) {
        tracker.feed(json.substr(i, 1));
        EXPECT_FALSE(tracker.closed()) << "byte " << i;
    }
    tracker.feed(json.substr(json.size() - 1, 1));
    EXPECT_TRUE(tracker.closed());
}

TEST(GuardSseJsonCloseTrackerTorture, ArraysDoNotAffectDepthOnlyBracesDo) {
    // Square brackets are not tracked at all -- only '{' / '}' move depth,
    // matching Go's switch which has no case for '[' or ']'.
    JsonCloseTracker tracker;
    tracker.feed(R"({"a":[1,2,3]})");
    EXPECT_TRUE(tracker.closed());
}

TEST(GuardSseJsonCloseTrackerTorture, EscapedBackslashBeforeQuoteDoesNotKeepStringOpen) {
    // `\\` is an escaped backslash, not an escaped quote -- the following `"`
    // legitimately closes the string. Fed one byte at a time to exercise the
    // escape flag across fragment boundaries.
    const std::string json = R"({"k":"a\\","z":1})";
    JsonCloseTracker one_shot;
    one_shot.feed(json);
    EXPECT_TRUE(one_shot.closed());

    JsonCloseTracker byte_by_byte;
    for (char c : json)
        byte_by_byte.feed(std::string_view(&c, 1));
    EXPECT_TRUE(byte_by_byte.closed());
}

// ---------------------------------------------------------------------------
// MaskedTextRecorder -- no dedicated Go test file; own coverage of the
// documented per-key, first-seen-order accumulation (masked_response.go).
// ---------------------------------------------------------------------------

TEST(GuardSseMaskedTextRecorder, EmptyRecorderReturnsEmptyTexts) {
    MaskedTextRecorder recorder;
    EXPECT_TRUE(recorder.texts().empty());
}

TEST(GuardSseMaskedTextRecorder, EmptyTextIsIgnoredAndCreatesNoEntry) {
    MaskedTextRecorder recorder;
    recorder.record("0/content", "");
    EXPECT_TRUE(recorder.texts().empty());
}

TEST(GuardSseMaskedTextRecorder, SingleKeyAccumulatesAcrossMultipleRecordCalls) {
    MaskedTextRecorder recorder;
    recorder.record("0/content", "Hello, ");
    recorder.record("0/content", "world");
    recorder.record("0/content", "!");
    EXPECT_EQ(recorder.texts(), (std::vector<std::string>{"Hello, world!"}));
}

TEST(GuardSseMaskedTextRecorder, MultipleKeysPreserveFirstSeenOrder) {
    MaskedTextRecorder recorder;
    recorder.record("1/content", "second key first write");
    recorder.record("0/content", "first key first write");
    recorder.record("1/content", " continued");
    recorder.record("0/content", " continued");

    EXPECT_EQ(recorder.texts(),
              (std::vector<std::string>{"second key first write continued", "first key first write continued"}));
}

TEST(GuardSseMaskedTextRecorder, InterleavedEmptyRecordsDoNotDisturbOrderOrContent) {
    MaskedTextRecorder recorder;
    recorder.record("a", "A1");
    recorder.record("b", "");  // no-op: "b" not yet registered
    recorder.record("a", "");  // no-op
    recorder.record("b", "B1");
    recorder.record("a", "A2");

    EXPECT_EQ(recorder.texts(), (std::vector<std::string>{"A1A2", "B1"}));
}

TEST(GuardSseMaskedTextRecorder, DistinctKeysStayIndependent) {
    MaskedTextRecorder recorder;
    recorder.record("0/content", "choice zero");
    recorder.record("1/content", "choice one");
    recorder.record("0/reasoning", "choice zero reasoning");

    EXPECT_EQ(recorder.texts(), (std::vector<std::string>{"choice zero", "choice one", "choice zero reasoning"}));
}

}  // namespace
