import { FormEvent, useEffect, useMemo, useState } from "react";
import { Bot, ChevronDown, LoaderCircle, Send, UserRound } from "lucide-react";
import { AgentTranscript } from "@/components/live/AgentTranscript";
import type { Transcript, TranscriptEvent } from "@/data/serverSource";

interface RunChatProps {
  runName: string;
  transcript: Transcript;
  working: boolean;
  exitCode: number | null;
  onSend: (message: string) => Promise<void>;
  onRefresh: () => Promise<void>;
  onRefreshControl?: () => Promise<void>;
}

type ConversationEntry = {
  id: string;
  timestamp: string;
  role: "user" | "assistant";
  content: string;
};

function responseMessage(event: TranscriptEvent): string | null {
  if (event.type !== "tool" || event.data.tool_name !== "respond_to_user") return null;
  const args = event.data.args;
  if (!args || typeof args !== "object" || Array.isArray(args)) return null;
  const message = (args as Record<string, unknown>).message;
  return typeof message === "string" && message.trim() ? message : null;
}

/**
 * Return prose that is addressed to the user from a transcript event.
 *
 * ``respond_to_user`` is the explicit pause/yield path, but an interactive
 * resume can also finish with a normal assistant message (for example when
 * the model answers and then the worker exits).  The activity view renders
 * those messages as ``Thinking``; the chat view must promote them to a real
 * assistant reply as well.
 */
function assistantMessage(event: TranscriptEvent): string | null {
  if (event.type !== "chat") return null;
  const role = String(event.data.role ?? "assistant").toLowerCase();
  if (role !== "assistant") return null;
  const content = event.data.content;
  return typeof content === "string" && content.trim() ? content : null;
}

function toolLabel(event: TranscriptEvent | undefined): string | null {
  if (!event || event.type !== "tool") return null;
  const name = typeof event.data.tool_name === "string" ? event.data.tool_name : "tool";
  return name.replaceAll("_", " ");
}

/** A per-run conversation view backed exclusively by that run's agents.db. */
export default function RunChat({
  runName,
  transcript,
  working,
  exitCode,
  onSend,
  onRefresh,
  onRefreshControl,
}: RunChatProps) {
  const [message, setMessage] = useState("");
  const [pendingMessage, setPendingMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [showActivity, setShowActivity] = useState(false);
  const [hasSubmitted, setHasSubmitted] = useState(false);

  const rootAgent = useMemo(
    () => transcript.agents.find((agent) => agent.parent_id === null) ?? null,
    [transcript.agents]
  );
  const rootEvents = useMemo(
    () => transcript.events.filter((event) => !rootAgent || event.agent_id === rootAgent.id),
    [rootAgent, transcript.events]
  );
  const conversation = useMemo<ConversationEntry[]>(
    () => {
      const entries: ConversationEntry[] = [];
      for (const event of rootEvents) {
        if (
          event.type === "chat" &&
          event.data.role === "user" &&
          typeof event.data.content === "string" &&
          event.data.content.trim()
        ) {
          entries.push({ id: event.id, timestamp: event.timestamp, role: "user", content: event.data.content });
          continue;
        }

        const assistant = assistantMessage(event);
        if (assistant) {
          entries.push({ id: event.id, timestamp: event.timestamp, role: "assistant", content: assistant });
          continue;
        }

        const reply = responseMessage(event);
        if (reply) {
          // Some model adapters emit the same prose as a normal assistant
          // message and then call respond_to_user. Keep only one bubble.
          const previous = entries[entries.length - 1];
          if (previous?.role === "assistant" && previous.content.trim() === reply.trim()) {
            continue;
          }
          entries.push({ id: event.id, timestamp: event.timestamp, role: "assistant", content: reply });
        }
      }
      return entries.sort((left, right) => left.timestamp.localeCompare(right.timestamp));
    },
    [rootEvents]
  );
  const activeTool = useMemo(
    () => [...rootEvents].reverse().find((event) => event.type === "tool" && event.data.status === "running"),
    [rootEvents]
  );

  useEffect(() => {
    if (working) setShowActivity(true);
  }, [working]);

  useEffect(() => {
    if (!pendingMessage) return;
    if (conversation.some((entry) => entry.role === "user" && entry.content === pendingMessage)) {
      setPendingMessage(null);
    }
  }, [conversation, pendingMessage]);

  // A completed scan normally stops ViewerApp's live polling. Follow-up chat
  // needs a small local poll while its short-lived worker is answering.
  useEffect(() => {
    if (!working && !sending) return;
    const refresh = () => {
      void onRefresh().catch(() => undefined);
      if (onRefreshControl) void onRefreshControl().catch(() => undefined);
    };
    refresh();
    const timer = window.setInterval(refresh, 900);
    return () => window.clearInterval(timer);
  }, [onRefresh, onRefreshControl, sending, working]);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const text = message.trim();
    if (!text || sending || working) return;
    setSending(true);
    setError(null);
    setPendingMessage(text);
    setMessage("");
    try {
      await onSend(text);
      setHasSubmitted(true);
    } catch (cause) {
      setPendingMessage(null);
      setMessage(text);
      setError(cause instanceof Error ? cause.message : "Không thể gửi tin nhắn.");
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="mx-auto max-w-4xl space-y-5">
      <div>
        <h1 className="text-2xl font-semibold text-white">Chat with agent</h1>
        <p className="mt-1 text-sm text-[#888]">
          Tiếp tục riêng run <span className="font-mono text-[#bbb]">{runName}</span>. Agent dùng lại lịch sử, evidence và findings của run này.
        </p>
      </div>

      <section className="overflow-hidden rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)]">
        <div className="max-h-[58vh] min-h-72 space-y-4 overflow-y-auto p-4 sm:p-5">
          {conversation.length === 0 && !pendingMessage ? (
            <p className="py-12 text-center text-sm text-[#666]">Chưa có hội thoại tiếp nối cho run này.</p>
          ) : (
            conversation.map((entry) => {
              const isUser = entry.role === "user";
              return (
                <article key={entry.id} className={`flex gap-3 ${isUser ? "justify-end" : "justify-start"}`}>
                  {!isUser && <Bot className="mt-1 h-4 w-4 flex-shrink-0 text-emerald-400" aria-hidden="true" />}
                  <div className={`max-w-[86%] whitespace-pre-wrap rounded-xl px-3.5 py-2.5 text-sm leading-relaxed ${isUser ? "bg-white text-black" : "border border-[#2a2a2a] bg-[#111] text-[#ddd]"}`}>
                    {entry.content}
                  </div>
                  {isUser && <UserRound className="mt-1 h-4 w-4 flex-shrink-0 text-[#aaa]" aria-hidden="true" />}
                </article>
              );
            })
          )}
          {pendingMessage && (
            <article className="flex justify-end gap-3">
              <div className="max-w-[86%] whitespace-pre-wrap rounded-xl bg-white px-3.5 py-2.5 text-sm leading-relaxed text-black opacity-70">{pendingMessage}</div>
              <UserRound className="mt-1 h-4 w-4 flex-shrink-0 text-[#aaa]" aria-hidden="true" />
            </article>
          )}
          {working && (
            <div className="flex items-center gap-2 px-1 text-sm text-emerald-400">
              <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden="true" />
              Agent đang xử lý{toolLabel(activeTool) ? `: ${toolLabel(activeTool)}` : " tin nhắn"}…
            </div>
          )}
          {hasSubmitted && !working && !sending && (
            <div className={`flex items-center gap-2 px-1 text-sm ${exitCode && exitCode !== 0 ? "text-red-300" : "text-emerald-400"}`}>
              {exitCode && exitCode !== 0
                ? `Phiên chat dừng với mã lỗi ${exitCode}. Mở phần hoạt động bên dưới để xem chi tiết.`
                : "Agent đã hoàn tất lượt xử lý. Phản hồi và hoạt động được lưu trong run này."}
            </div>
          )}
        </div>
        {rootAgent && (
          <details
            open={showActivity}
            onToggle={(event) => setShowActivity((event.currentTarget as HTMLDetailsElement).open)}
            className="border-t border-[#222] bg-black/30"
          >
            <summary className="flex cursor-pointer list-none items-center gap-2 px-4 py-3 text-sm text-[#aaa] hover:text-white">
              <ChevronDown className={`h-4 w-4 transition-transform ${showActivity ? "rotate-180" : ""}`} aria-hidden="true" />
              {working ? "Hoạt động và thinking của agent" : "Xem hoạt động và thinking của agent"}
              {working && <span className="ml-auto h-2 w-2 rounded-full bg-emerald-400 animate-pulse" aria-label="Agent đang chạy" />}
            </summary>
            <div className="max-h-[42vh] overflow-y-auto border-t border-[#1a1a1a] px-4 py-2">
              <AgentTranscript agent={rootAgent} events={rootEvents} showHeader={false} />
            </div>
          </details>
        )}
        <form onSubmit={submit} className="border-t border-[#222] p-3 sm:p-4">
          {error && <p className="mb-2 text-xs text-red-300">{error}</p>}
          <div className="flex gap-2">
            <textarea
              value={message}
              onChange={(event) => setMessage(event.target.value)}
              placeholder="Hỏi về kết quả hoặc giao thêm tác vụ trong phạm vi run…"
              rows={2}
              disabled={working || sending}
              className="min-h-12 flex-1 resize-y rounded-lg border border-[#333] bg-black px-3 py-2 text-sm text-white outline-none placeholder:text-[#666] focus:border-[#666] disabled:cursor-not-allowed disabled:opacity-60"
            />
            <button
              type="submit"
              disabled={!message.trim() || working || sending}
              className="inline-flex h-10 self-end cursor-pointer items-center gap-1.5 rounded-lg bg-white px-3 text-sm font-semibold text-black transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {sending ? <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Send className="h-4 w-4" aria-hidden="true" />}
              Gửi
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
