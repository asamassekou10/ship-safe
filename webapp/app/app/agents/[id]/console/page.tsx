'use client';
import { useEffect, useRef, useState, useCallback } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import styles from './console.module.css';

// ── Types ─────────────────────────────────────────────────────────────────────

interface ToolCall { tool: string; args: Record<string, unknown>; result?: string }

interface Message {
  id:        string;
  role:      'user' | 'assistant';
  content:   string;
  toolCalls: ToolCall[];
  streaming: boolean;
  error:     boolean;
}

interface Run {
  id:         string;
  status:     string;
  tokensUsed: number | null;
  startedAt:  string;
  messages:   Array<{ content: string }>;
}

interface AgentInfo {
  id:     string;
  name:   string;
  slug:   string;
  status: string;
  tools:  Array<{ name: string }>;
  memoryProvider: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function uid() { return Math.random().toString(36).slice(2); }

function timeAgo(date: string) {
  const s = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

/** Minimal markdown → HTML: bold, italic, code, code blocks, links */
function renderMarkdown(text: string) {
  return text
    .replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>')
    .replace(/\n/g, '<br/>');
}

// ── Tool call card ─────────────────────────────────────────────────────────────

function ToolCard({ tc }: { tc: ToolCall }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={styles.toolCard}>
      <button className={styles.toolHeader} onClick={() => setOpen(o => !o)}>
        <span className={styles.toolIcon}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
        </span>
        <span className={styles.toolName}>{tc.tool}</span>
        {tc.result && <span className={styles.toolDone}>✓</span>}
        <span className={styles.toolChevron}>{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div className={styles.toolBody}>
          {Object.keys(tc.args).length > 0 && (
            <div className={styles.toolSection}>
              <div className={styles.toolSectionLabel}>Input</div>
              <pre className={styles.toolPre}>{JSON.stringify(tc.args, null, 2)}</pre>
            </div>
          )}
          {tc.result && (
            <div className={styles.toolSection}>
              <div className={styles.toolSectionLabel}>Output</div>
              <pre className={styles.toolPre}>{tc.result}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Message bubble ─────────────────────────────────────────────────────────────

function MessageBubble({ msg }: { msg: Message }) {
  const isUser = msg.role === 'user';
  return (
    <div className={`${styles.msg} ${isUser ? styles.msgUser : styles.msgAssistant}`}>
      <div className={styles.msgAvatar}>
        {isUser ? (
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        ) : (
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
        )}
      </div>
      <div className={styles.msgBody}>
        {msg.toolCalls.map((tc, i) => <ToolCard key={i} tc={tc} />)}
        {msg.error ? (
          <div className={styles.msgError}>{msg.content}</div>
        ) : (
          <div
            className={styles.msgText}
            dangerouslySetInnerHTML={{ __html: renderMarkdown(msg.content) }}
          />
        )}
        {msg.streaming && <span className={styles.cursor} aria-hidden="true" />}
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ConsolePage() {
  const { id } = useParams<{ id: string }>();

  const [agent,    setAgent]    = useState<AgentInfo | null>(null);
  const [runs,     setRuns]     = useState<Run[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input,    setInput]    = useState('');
  const [runId,    setRunId]    = useState<string | null>(null);
  const [sending,  setSending]  = useState(false);
  const [loading,  setLoading]  = useState(true);
  const [sideOpen, setSideOpen] = useState(false);

  const bottomRef  = useRef<HTMLDivElement>(null);
  const textaRef   = useRef<HTMLTextAreaElement>(null);
  const abortRef   = useRef<AbortController | null>(null);

  // Load agent info + run history
  const loadAgent = useCallback(async () => {
    const [agentRes, runsRes] = await Promise.all([
      fetch(`/api/agents/${id}`),
      fetch(`/api/agents/${id}/chat`),
    ]);
    if (!agentRes.ok) return;
    const { agent } = await agentRes.json();
    setAgent(agent);
    if (runsRes.ok) {
      const { runs } = await runsRes.json();
      setRuns(runs ?? []);
    }
    setLoading(false);
  }, [id]);

  useEffect(() => { loadAgent(); }, [loadAgent]);

  // Load a past run's messages
  async function loadRun(rid: string) {
    setRunId(rid);
    const res  = await fetch(`/api/agents/${id}/chat?runId=${rid}`);
    if (!res.ok) return;
    const { messages: msgs } = await res.json();
    setMessages(msgs.map((m: { id: string; role: 'user' | 'assistant'; content: string; toolCalls?: ToolCall[] }) => ({
      id:        m.id,
      role:      m.role,
      content:   m.content,
      toolCalls: m.toolCalls ?? [],
      streaming: false,
      error:     false,
    })));
    setSideOpen(false);
  }

  function newConversation() {
    setRunId(null);
    setMessages([]);
    setSideOpen(false);
    textaRef.current?.focus();
  }

  // Scroll to bottom on new messages
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Auto-resize textarea
  function handleInputChange(e: React.ChangeEvent<HTMLTextAreaElement>) {
    setInput(e.target.value);
    e.target.style.height = 'auto';
    e.target.style.height = Math.min(e.target.scrollHeight, 160) + 'px';
  }

  async function send() {
    const text = input.trim();
    if (!text || sending) return;

    setInput('');
    if (textaRef.current) textaRef.current.style.height = 'auto';
    setSending(true);

    // Optimistic user message
    const userMsgId = uid();
    setMessages(prev => [...prev, {
      id: userMsgId, role: 'user', content: text,
      toolCalls: [], streaming: false, error: false,
    }]);

    // Placeholder assistant message
    const asstMsgId = uid();
    setMessages(prev => [...prev, {
      id: asstMsgId, role: 'assistant', content: '',
      toolCalls: [], streaming: true, error: false,
    }]);

    const ctrl = new AbortController();
    abortRef.current = ctrl;

    try {
      const res = await fetch(`/api/agents/${id}/chat`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ message: text, runId }),
        signal:  ctrl.signal,
      });

      if (!res.ok || !res.body) {
        const err = await res.json().catch(() => ({ error: 'Failed' }));
        setMessages(prev => prev.map(m =>
          m.id === asstMsgId
            ? { ...m, content: err.error || 'Something went wrong', streaming: false, error: true }
            : m
        ));
        return;
      }

      const reader  = res.body.getReader();
      const decoder = new TextDecoder();
      let   pending = '';
      let   currentEvent = '';
      const pendingToolCalls: ToolCall[] = [];

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        pending += decoder.decode(value, { stream: true });

        const lines = pending.split('\n');
        pending = lines.pop() ?? '';

        for (const line of lines) {
          if (line.startsWith('event: ')) {
            currentEvent = line.slice(7).trim();
          } else if (line.startsWith('data: ')) {
            const raw = line.slice(6);
            try {
              const data = JSON.parse(raw);

              if (currentEvent === 'run') {
                setRunId(data.runId);

              } else if (currentEvent === 'token') {
                const chunk = typeof data === 'string' ? data : '';
                setMessages(prev => prev.map(m =>
                  m.id === asstMsgId ? { ...m, content: m.content + chunk } : m
                ));

              } else if (currentEvent === 'tool_call') {
                pendingToolCalls.push({ tool: data.tool, args: data.args ?? {} });
                setMessages(prev => prev.map(m =>
                  m.id === asstMsgId ? { ...m, toolCalls: [...pendingToolCalls] } : m
                ));

              } else if (currentEvent === 'tool_result') {
                const last = pendingToolCalls[pendingToolCalls.length - 1];
                if (last && last.tool === data.tool) last.result = data.result;
                setMessages(prev => prev.map(m =>
                  m.id === asstMsgId ? { ...m, toolCalls: [...pendingToolCalls] } : m
                ));

              } else if (currentEvent === 'error') {
                setMessages(prev => prev.map(m =>
                  m.id === asstMsgId
                    ? { ...m, content: data.message || 'Agent error', streaming: false, error: true }
                    : m
                ));

              } else if (currentEvent === 'done') {
                setMessages(prev => prev.map(m =>
                  m.id === asstMsgId ? { ...m, streaming: false } : m
                ));
                // Refresh run list
                loadAgent();
              }
            } catch { /* ignore malformed SSE */ }
          }
        }
      }
    } catch (e) {
      if ((e as Error).name !== 'AbortError') {
        setMessages(prev => prev.map(m =>
          m.id === asstMsgId
            ? { ...m, content: 'Connection lost. Is the agent running?', streaming: false, error: true }
            : m
        ));
      }
    } finally {
      setSending(false);
      abortRef.current = null;
      setMessages(prev => prev.map(m =>
        m.id === asstMsgId && m.streaming ? { ...m, streaming: false } : m
      ));
    }
  }

  function stop() {
    abortRef.current?.abort();
    setSending(false);
  }

  function handleKey(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  if (loading) return <div className={styles.page}><div className={styles.skeleton} /></div>;

  const isLive = agent?.status === 'deployed' || agent?.status === 'running';

  return (
    <div className={styles.shell}>
      {/* ── Sidebar ──────────────────────────────────────────── */}
      <aside className={`${styles.sidebar} ${sideOpen ? styles.sidebarOpen : ''}`}>
        <div className={styles.sidebarHeader}>
          <Link href={`/app/agents/${id}`} className={styles.backLink}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><polyline points="15 18 9 12 15 6"/></svg>
            {agent?.name}
          </Link>
          <button className={styles.newChatBtn} onClick={newConversation} title="New conversation">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          </button>
        </div>

        <div className={styles.sidebarSection}>Past conversations</div>
        <div className={styles.runList}>
          {runs.length === 0 && (
            <div className={styles.runEmpty}>No conversations yet</div>
          )}
          {runs.map(r => (
            <button
              key={r.id}
              className={`${styles.runItem} ${r.id === runId ? styles.runActive : ''}`}
              onClick={() => loadRun(r.id)}
            >
              <div className={styles.runPreview}>
                {r.messages[0]?.content?.slice(0, 48) || 'Empty conversation'}
              </div>
              <div className={styles.runMeta}>
                {timeAgo(r.startedAt)}
                {r.tokensUsed ? ` · ${r.tokensUsed} tokens` : ''}
              </div>
            </button>
          ))}
        </div>

        {agent && (
          <div className={styles.agentInfo}>
            <div className={styles.agentInfoRow}>
              <span className={styles.agentInfoKey}>Memory</span>
              <span className={styles.agentInfoVal}>{agent.memoryProvider}</span>
            </div>
            <div className={styles.agentInfoRow}>
              <span className={styles.agentInfoKey}>Tools</span>
              <span className={styles.agentInfoVal}>{agent.tools.length}</span>
            </div>
          </div>
        )}
      </aside>

      {/* ── Main chat area ────────────────────────────────────── */}
      <div className={styles.main}>
        {/* Topbar */}
        <div className={styles.topbar}>
          <button className={styles.menuBtn} onClick={() => setSideOpen(o => !o)} aria-label="Toggle sidebar">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
          </button>
          <div className={styles.topbarTitle}>{agent?.name}</div>
          <div className={styles.topbarStatus}>
            <span className={`${styles.statusDot} ${isLive ? styles.statusDotLive : styles.statusDotOff}`} />
            {isLive ? 'Live' : 'Offline'}
          </div>
        </div>

        {/* Messages */}
        <div className={styles.messages}>
          {messages.length === 0 && (
            <div className={styles.emptyChat}>
              <div className={styles.emptyChatIcon}>
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
              </div>
              <div className={styles.emptyChatTitle}>
                {isLive ? `Chat with ${agent?.name}` : 'Agent is offline'}
              </div>
              <div className={styles.emptyChatDesc}>
                {isLive
                  ? 'Send a message to start the conversation.'
                  : 'Deploy this agent first to start chatting.'}
              </div>
              {!isLive && (
                <Link href={`/app/agents/${id}`} className={styles.deployLink}>
                  Go to agent →
                </Link>
              )}
            </div>
          )}

          {messages.map(msg => <MessageBubble key={msg.id} msg={msg} />)}
          <div ref={bottomRef} />
        </div>

        {/* Input */}
        <div className={styles.inputArea}>
          {!isLive && (
            <div className={styles.offlineBanner}>
              Agent is not running.
              <Link href={`/app/agents/${id}`}> Deploy it →</Link>
            </div>
          )}
          <div className={styles.inputBox}>
            <textarea
              ref={textaRef}
              className={styles.textarea}
              placeholder={isLive ? 'Message the agent… (Enter to send, Shift+Enter for newline)' : 'Agent offline'}
              value={input}
              onChange={handleInputChange}
              onKeyDown={handleKey}
              disabled={!isLive || sending}
              rows={1}
            />
            {sending ? (
              <button className={styles.stopBtn} onClick={stop} title="Stop">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="4" y="4" width="16" height="16" rx="2"/></svg>
              </button>
            ) : (
              <button
                className={styles.sendBtn}
                onClick={send}
                disabled={!isLive || !input.trim()}
                title="Send (Enter)"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Mobile overlay */}
      {sideOpen && <div className={styles.overlay} onClick={() => setSideOpen(false)} />}
    </div>
  );
}
