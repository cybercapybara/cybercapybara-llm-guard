/**
 * @file Common.hpp
 * @brief Dialect-agnostic SSE frame machinery: split raw upstream bytes into
 *        frames, classify a frame's `data:`/`[DONE]` payload, rebuild a bare
 *        data frame, track a streamed JSON object's close, and accumulate
 *        masked (pre-demask) text for the audit trail.
 * @details Ports `internal/sseproc/common/{frame,eventframe,json_depth,
 *          masked_response}.go`, read directly:
 *
 *          **split_frames** ports `SplitFrames` + `FindFrameSeparator`
 *          (frame.go:15-44). A frame boundary is `"\n\n"` or `"\r\n\r\n"`;
 *          when both are present in the remaining buffer the EARLIER one
 *          wins, ties (impossible here -- the two separators can never start
 *          at the same offset) broken toward CRLF exactly as Go's `if
 *          crlfIdx != -1 && (lfIdx == -1 || crlfIdx < lfIdx)` does. Each
 *          returned frame INCLUDES its trailing separator (`data[:end]`);
 *          `tail` is whatever remains after the last separator -- an
 *          unterminated final frame the caller must carry into the next
 *          chunk (Go returns the residual `data` itself, which this port
 *          mirrors as a `string_view` into the same buffer `buf` came from,
 *          so `frames`/`tail` are only valid as long as the caller keeps
 *          that buffer alive, same lifetime contract Go's byte slices have).
 *
 *          **classify_frame** ports `ClassifyFrame` (eventframe.go:56-108).
 *          Frames are walked line by line via `NextLine` (split on `'\n'`,
 *          trailing `'\r'` trimmed before comparison so CRLF is supported);
 *          blank lines are skipped. A `"data:"` line (the SSE-legal form
 *          WITHOUT the space -- `dataLinePrefix`, distinct from the
 *          canonical `DataPrefix` `build_event_frame` emits) has at most one
 *          leading space stripped from its payload per the SSE spec. A
 *          payload byte-equal to `"[DONE]"` short-circuits to `FrameKind::
 *          Done` immediately, discarding anything accumulated so far --
 *          exactly Go's early `return pf` before the multi-line join or the
 *          final `len(dataPayload) > 0` check ever run. Multiple `data:`
 *          lines in one frame join with `'\n'` (SSE spec; Go's `joined :=
 *          append(dataPayload, '\n', payload...)`), and -- the one place a
 *          nil/non-nil distinction Go makes is NOT mirrored by a truthiness
 *          check here -- the frame classifies as `FrameKind::Event` only
 *          when the joined data is non-empty (Go's `if len(dataPayload) > 0`
 *          gate, not a nil check: a single `"data:\n\n"` line with an empty
 *          payload leaves `dataPayload` a non-nil EMPTY slice, so Go falls
 *          through to `FramePassthrough` -- this port keys the same decision
 *          off `!data.empty()` after the join, which agrees on every case
 *          including the two-empty-`data:`-lines edge case where the joining
 *          `'\n'` alone makes the result non-empty). `event:`/`id:`/
 *          `retry:` lines and SSE comments (`:` prefix) match neither
 *          prefix and are silently skipped for classification purposes,
 *          same as Go's switch with only two cases -- the contract here
 *          (phase3-interfaces.md) does not surface the event name, so
 *          unlike Go's `ParsedFrame.Event` this port has nothing to set for
 *          them regardless. `raw` is always the verbatim input frame
 *          (`Original` in Go), letting a passthrough caller re-emit it
 *          byte-identically.
 *
 *          **build_event_frame** ports the DATA-FRAME half of
 *          `BuildEventFrame` (eventframe.go:123-132): `"data: " + data +
 *          "\n\n"`, byte-for-byte (`DataPrefix` is `"data: "` -- six bytes,
 *          WITH the space -- unlike the loose `data:` classify_frame
 *          accepts on input). Go's function also takes an `eventName` and
 *          prepends `"event: " + eventName + "\n"`; the interfaces contract
 *          (phase3-interfaces.md) intentionally narrows this shared helper
 *          to the single-argument, data-only form -- the bare `data: ...`
 *          frame shape every dialect can build without needing this file to
 *          know about named events. A dialect that also emits an `event:`
 *          line (Anthropic Messages, OpenAI Responses) composes that prefix
 *          itself in its own processor header.
 *
 *          **JsonCloseTracker** ports `JSONCloseTracker` (json_depth.go).
 *          Brace depth, in-string state and backslash-escape state all
 *          carry ACROSS `feed` calls (fragments), so a value split
 *          mid-string (`{"k":"a` + `b}c"}`) never mistakes the in-string
 *          `'}'` for a real close -- exactly the torture case Go's own test
 *          file exists to pin down. Go's `Feed` returns a per-call bool
 *          ("did the object close IN THIS fragment"); the interfaces
 *          contract here instead gives `feed` a `void` return and a
 *          separate `closed() const` query, read as "has the top-level
 *          object completed [since the last reset]". This port implements
 *          `closed()` as STICKY: a private flag flips true the moment depth
 *          returns to zero after having opened (Go's `t.opened && t.depth ==
 *          0` condition, checked the same way, once per byte) and stays true
 *          until `reset()`. That is observably equivalent to Go's
 *          transient-return contract for every caller pattern the Go tests
 *          exercise (feed, then check once) -- the FIRST fragment at which
 *          `closed()` flips from false to true is exactly the fragment
 *          index at which Go's `Feed` would have returned true.
 *
 *          **MaskedTextRecorder** ports `MaskedTextRecorder` (masked_
 *          response.go). `record` (Go: `Add`) ignores empty text so a
 *          buffering/flush no-op never creates a spurious key entry with
 *          nothing in it; the first `record` for a given key establishes
 *          that key's position in first-seen order, and every later
 *          `record` for the same key appends (Go's `strings.Builder`,
 *          mirrored here with a plain `std::string`, is equally
 *          single-writer-append-only). `texts` (Go: `Texts`) walks keys in
 *          that first-seen order and returns each key's fully concatenated
 *          text -- ONE string per key, not a list of fragments -- skipping
 *          any key whose accumulated text is (defensively) still empty, the
 *          same belt-and-suspenders check Go's `if s := ...; s != ""` makes
 *          even though `record`'s own empty-text guard already makes that
 *          state unreachable in practice.
 */

#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Guard::Sse {

/// Result of `split_frames`: complete frames (each including its trailing
/// separator) plus whatever incomplete tail remains. Both `frames` and
/// `tail` are views into the SAME buffer passed to `split_frames` -- the
/// caller must keep that buffer alive for as long as it uses this result.
struct FrameSplit {
    std::vector<std::string_view> frames;
    std::string_view tail;
};

namespace detail {

inline constexpr std::string_view kFrameSepLF = "\n\n";
inline constexpr std::string_view kFrameSepCRLF = "\r\n\r\n";
inline constexpr std::string_view kDataLinePrefix = "data:";  // no space: the loose, SSE-legal form
inline constexpr std::string_view kDoneSentinel = "[DONE]";
inline constexpr std::string_view kDataPrefix = "data: ";  // canonical, with space: what we EMIT

/// Ports `FindFrameSeparator` (frame.go:36-44): the earliest of `"\n\n"` and
/// `"\r\n\r\n"` in `data`, CRLF winning ties. `idx == npos` means neither
/// separator is present.
struct FoundSeparator {
    std::string_view sep;
    std::size_t idx;
};

inline FoundSeparator find_frame_separator(std::string_view data) {
    const std::size_t lf_idx = data.find(kFrameSepLF);
    const std::size_t crlf_idx = data.find(kFrameSepCRLF);
    if (crlf_idx != std::string_view::npos && (lf_idx == std::string_view::npos || crlf_idx < lf_idx))
        return FoundSeparator{kFrameSepCRLF, crlf_idx};
    return FoundSeparator{kFrameSepLF, lf_idx};
}

/// Ports `NextLine` (eventframe.go:113-119): the next `'\n'`-delimited line
/// (without the `'\n'`) and the remainder. No trailing newline left ->
/// the whole input is the line and the remainder is empty.
inline std::string_view next_line(std::string_view buf, std::string_view& rest) {
    const std::size_t idx = buf.find('\n');
    if (idx == std::string_view::npos) {
        rest = std::string_view{};
        return buf;
    }
    rest = buf.substr(idx + 1);
    return buf.substr(0, idx);
}

/// Trims one trailing `'\r'`, matching Go's `bytes.TrimRight(line, "\r")`
/// (which, applied to a single line, can only ever strip zero or one byte).
inline std::string_view trim_trailing_cr(std::string_view line) {
    if (!line.empty() && line.back() == '\r')
        line.remove_suffix(1);
    return line;
}

}  // namespace detail

/// Splits raw SSE bytes into complete frames and a leftover tail. Ports
/// `SplitFrames` (frame.go:19-31) exactly.
inline FrameSplit split_frames(std::string_view buf) {
    FrameSplit result;
    while (!buf.empty()) {
        const detail::FoundSeparator found = detail::find_frame_separator(buf);
        if (found.idx == std::string_view::npos) {
            result.tail = buf;
            return result;
        }
        const std::size_t end = found.idx + found.sep.size();
        result.frames.push_back(buf.substr(0, end));
        buf.remove_prefix(end);
    }
    result.tail = buf;  // empty: every byte belonged to a complete frame
    return result;
}

/// Classification of one SSE frame. Ports Go's `FrameKind` (eventframe.go:
/// 21-32); `FramePassthrough` covers comments, empty frames and anything
/// this file doesn't need to inspect.
enum class FrameKind {
    Event,
    Done,
    Passthrough,
};

/// Result of `classify_frame`. `data` is the joined multi-line `data:`
/// payload (only meaningful when `kind == FrameKind::Event`); `raw` is the
/// verbatim input frame, valid for as long as the buffer passed to
/// `classify_frame` stays alive. Ports Go's `ParsedFrame` (eventframe.go:
/// 34-46) minus the `Event` field, which phase3-interfaces.md's contract
/// does not surface here.
struct ClassifiedFrame {
    FrameKind kind{FrameKind::Passthrough};
    std::string data;
    std::string_view raw;
};

/// Inspects one SSE frame (including its trailing separator) line by line
/// and classifies it. Ports `ClassifyFrame` (eventframe.go:56-108) -- see
/// the file-level note for the exact `[DONE]`-short-circuit and
/// empty-payload edge cases this mirrors.
inline ClassifiedFrame classify_frame(std::string_view frame) {
    ClassifiedFrame result;
    result.raw = frame;

    bool have_data = false;
    std::string_view rest = frame;
    while (!rest.empty()) {
        const std::string_view line = detail::next_line(rest, rest);
        const std::string_view trimmed = detail::trim_trailing_cr(line);
        if (trimmed.empty())
            continue;

        if (trimmed.substr(0, detail::kDataLinePrefix.size()) != detail::kDataLinePrefix)
            continue;  // event:/id:/retry:/comment lines: unclassified, matches Go

        std::string_view payload = trimmed.substr(detail::kDataLinePrefix.size());
        if (!payload.empty() && payload.front() == ' ')
            payload.remove_prefix(1);  // SSE spec: strip one optional leading space

        if (payload == detail::kDoneSentinel) {
            result.kind = FrameKind::Done;
            return result;  // discards anything already joined, matching Go's early return
        }

        if (!have_data) {
            result.data.assign(payload);
            have_data = true;
        } else {
            result.data.push_back('\n');
            result.data.append(payload);
        }
    }

    if (!result.data.empty())
        result.kind = FrameKind::Event;
    return result;
}

/// Rebuilds a bare SSE data frame: `"data: " + data + "\n\n"`, byte-for-byte.
/// Ports the data-only half of `BuildEventFrame` (eventframe.go:123-132) --
/// see the file-level note for why this shared helper omits the `event:`
/// line Go's two-argument version also builds.
inline std::string build_event_frame(std::string_view data) {
    std::string out;
    out.reserve(detail::kDataPrefix.size() + data.size() + 2);
    out.append(detail::kDataPrefix);
    out.append(data);
    out.append("\n\n");
    return out;
}

/// Tracks the brace depth of a JSON object streamed across multiple
/// fragments -- string-literal and backslash-escape state carry ACROSS
/// `feed` calls, so an in-string `'}'` or an escaped quote can never be
/// mistaken for real JSON structure regardless of where a fragment boundary
/// falls. Ports `JSONCloseTracker` (json_depth.go); see the file-level note
/// for how its sticky `closed()` corresponds to Go's per-call return value.
/// The default-constructed tracker is ready to use.
class JsonCloseTracker {
public:
    /// Consumes one fragment in arrival order, updating depth/string/escape
    /// state byte by byte. `closed()` flips true the moment depth returns to
    /// zero after having opened (Go: `t.opened && t.depth == 0`) and stays
    /// true until `reset()`.
    void feed(std::string_view fragment) {
        for (const char c : fragment) {
            if (escaped_) {
                escaped_ = false;
                continue;
            }
            if (c == '\\') {
                escaped_ = true;
                continue;
            }
            if (c == '"') {
                in_string_ = !in_string_;
                continue;
            }
            if (in_string_)
                continue;

            if (c == '{') {
                ++depth_;
                opened_ = true;
            } else if (c == '}') {
                --depth_;
                if (opened_ && depth_ == 0)
                    closed_ = true;
            }
        }
    }

    /// Whether the top-level JSON object has completed since construction
    /// or the last `reset()`.
    bool closed() const { return closed_; }

    /// Returns the tracker to its just-constructed state, ready to track a
    /// fresh JSON object.
    void reset() {
        depth_ = 0;
        in_string_ = false;
        escaped_ = false;
        opened_ = false;
        closed_ = false;
    }

private:
    int depth_{0};
    bool in_string_{false};
    bool escaped_{false};
    bool opened_{false};  // saw at least one '{' -- guards a stray leading '}'
    bool closed_{false};
};

/// Accumulates the masked (pre-demask) text of an SSE response, grouped by
/// stream key and concatenated in first-seen key order, for the audit
/// trail. Ports `MaskedTextRecorder` (masked_response.go). Tool-call
/// argument fragments are deliberately never fed here by callers -- this
/// class itself has no opinion on what a "key" is, it only orders and
/// concatenates whatever it is given.
class MaskedTextRecorder {
public:
    /// Appends `text` to the accumulated text for `key`. A no-op for empty
    /// `text`, so buffering/flush calls that produce nothing never create a
    /// spurious empty entry. The first non-empty `record` for a given key
    /// fixes that key's position in `texts()`'s output order.
    void record(const std::string& key, std::string_view text) {
        if (text.empty())
            return;
        auto it = by_key_.find(key);
        if (it == by_key_.end()) {
            order_.push_back(key);
            it = by_key_.emplace(key, std::string()).first;
        }
        it->second.append(text);
    }

    /// Returns the accumulated text of each recorded key, in first-seen
    /// order -- one fully concatenated string per key. Returns an empty
    /// vector when nothing was recorded.
    std::vector<std::string> texts() const {
        std::vector<std::string> out;
        out.reserve(order_.size());
        for (const std::string& key : order_) {
            const std::string& text = by_key_.at(key);
            if (!text.empty())
                out.push_back(text);
        }
        return out;
    }

private:
    std::unordered_map<std::string, std::string> by_key_;
    std::vector<std::string> order_;
};

}  // namespace Guard::Sse
