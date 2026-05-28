import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  ArrowRight,
  BarChart3,
  BookMarked,
  Check,
  CircleHelp,
  Clock,
  Copy,
  Eye,
  FileText,
  Globe,
  History,
  KeyRound,
  Library,
  Lock,
  LogOut,
  Mail,
  MoreHorizontal,
  Plus,
  Search,
  Send,
  Settings,
  ShieldAlert,
  Share2,
  Sparkles,
  Upload,
  Users
} from "lucide-react";
import logoMark from "./assets/brand/logo.png";
import "./styles.css";

type Session = { user: null | User };
type User = { id: string; email: string; name: string; provider: string; email_confirmed?: string };
type Publication = {
  id: string;
  title: string;
  slug: string;
  mode?: string;
  visibility: string;
  require_registration: boolean;
  files: string[];
  created_at: string;
};
type AccessLog = {
  id: string;
  publication_id: string;
  slug: string;
  path: string;
  ip: string;
  user_agent: string;
  email?: string;
  allowed: boolean;
  status: number;
  created_at: string;
};
type SignedAccessProof = {
  id: string;
  publication_id: string;
  email: string;
  ip: string;
  user_agent: string;
  token_id: string;
  created_at: string;
};
type Stats = { visits: number; logs: AccessLog[]; signed_proofs?: SignedAccessProof[] };
type Share = { id: string; publication_id: string; email: string; user_id?: string; created_at: string };
type HistoryEntry = { publication: Publication; last_opened_at: string; path: string; visits: number };
type BookmarkRecord = { id: string; user_id: string; publication_id: string; kind: string; created_at: string };
type BookmarkEntry = { bookmark: BookmarkRecord; publication: Publication };
type Comment = {
  id: string;
  publication_id: string;
  parent_id?: string;
  email?: string;
  body: string;
  scope: string;
  anchor_text?: string;
  created_at: string;
  archived_at?: string;
  deleted_at?: string;
};
type AbuseCase = {
  id: string;
  publication_id: string;
  slug: string;
  reporter_email?: string;
  reporter_ip: string;
  reason: string;
  status: string;
  severity: string;
  analysis_summary?: string;
  auto_blocked: boolean;
  created_at: string;
};
type UploadedFile = { name: string; content: string; size: number };
type PublishDraft = {
  title: string;
  visibility: string;
  recipients: string;
  files: UploadedFile[];
};
type PublishComposerProps = {
  draft: PublishDraft;
  setDraft: React.Dispatch<React.SetStateAction<PublishDraft>>;
  publishPublication: () => void;
};
type NavKey = "Library" | "History" | "Shared with me" | "Bookmarks" | "Recipients" | "Agent keys" | "Activity" | "Settings";
const llmsHelpUrl = `${window.location.origin}/llms.txt`;

const visibilityHelp: Record<string, string> = {
  private: "Private: only you can open it from the console.",
  recipients: "Recipients: only specific emails or allowed domains can open it.",
  signed: "Signed access: each recipient receives an email token and reading proof is recorded.",
  public: "Link access: anyone with the link can open it."
};

const navItems: Array<{ key: NavKey; icon: React.ElementType }> = [
  { key: "Library", icon: Library },
  { key: "History", icon: History },
  { key: "Shared with me", icon: Share2 },
  { key: "Bookmarks", icon: BookMarked },
  { key: "Recipients", icon: Users },
  { key: "Agent keys", icon: KeyRound },
  { key: "Activity", icon: Activity },
  { key: "Settings", icon: Settings }
];

function App() {
  const [session, setSession] = useState<Session>({ user: null });
  const [publications, setPublications] = useState<Publication[]>([]);
  const [active, setActive] = useState<NavKey>("Library");
  const [selectedId, setSelectedId] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [notice, setNotice] = useState("");
  const [googleClientId, setGoogleClientId] = useState("");
  const [signupEmail, setSignupEmail] = useState("");
  const [shareEmail, setShareEmail] = useState("");
  const [signedAccessEmail, setSignedAccessEmail] = useState("");
  const [statsByPublication, setStatsByPublication] = useState<Record<string, Stats>>({});
  const [sharesByPublication, setSharesByPublication] = useState<Record<string, Share[]>>({});
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [sharedWithMe, setSharedWithMe] = useState<Publication[]>([]);
  const [bookmarks, setBookmarks] = useState<BookmarkEntry[]>([]);
  const [commentsByPublication, setCommentsByPublication] = useState<Record<string, Comment[]>>({});
  const [replyTo, setReplyTo] = useState("");
  const [replyBody, setReplyBody] = useState("");
  const [abuseCases, setAbuseCases] = useState<AbuseCase[]>([]);
  const [draft, setDraft] = useState<PublishDraft>({
    title: "",
    visibility: "public",
    recipients: "",
    files: []
  });

  const selected = useMemo(() => publications.find((publication) => publication.id === selectedId) || publications[0], [publications, selectedId]);
  const totalVisits = useMemo(
    () => Object.values(statsByPublication).reduce((sum, stat) => sum + (stat?.visits || 0), 0),
    [statsByPublication]
  );

  useEffect(() => {
    refreshSession();
    void loadAuthConfig();
  }, []);

  useEffect(() => {
    if (session.user) {
      void refreshPublications();
    }
  }, [session.user]);

  useEffect(() => {
    if (selected) {
      void loadStats(selected);
      void loadShares(selected);
    }
  }, [selected?.id]);

  async function refreshSession() {
    const data = await api<Session>("/api/session");
    setSession(data);
  }

  async function loadAuthConfig() {
    const data = await api<{ google_client_id?: string }>("/api/auth/config");
    setGoogleClientId(data.google_client_id || "");
  }

  async function refreshPublications() {
    const data = await api<{ publications?: Publication[] }>("/api/library");
    const nextPublications = data.publications || [];
    setPublications(nextPublications);
    setSelectedId((current) => current || nextPublications[0]?.id || "");
    await Promise.all(nextPublications.slice(0, 6).map((publication) => loadStats(publication)));
    await Promise.all(nextPublications.slice(0, 6).map((publication) => loadShares(publication)));
    await loadAbuseCases();
    await Promise.all([loadHistory(), loadSharedWithMe(), loadBookmarks()]);
  }

  async function loadHistory() {
    const data = await api<{ history?: HistoryEntry[] }>("/api/history");
    setHistory(data.history || []);
  }

  async function loadSharedWithMe() {
    const data = await api<{ publications?: Publication[] }>("/api/shared-with-me");
    setSharedWithMe(data.publications || []);
  }

  async function loadBookmarks() {
    const data = await api<{ bookmarks?: BookmarkEntry[] }>("/api/bookmarks");
    setBookmarks(data.bookmarks || []);
  }

  async function loadStats(publication: Publication) {
    const stat = await api<Stats>(`/api/library/${publication.id}/stats`);
    setStatsByPublication((current) => ({ ...current, [publication.id]: stat }));
  }

  async function loadShares(publication: Publication) {
    const data = await api<{ shares?: Share[] }>(`/api/library/${publication.id}/shares`);
    setSharesByPublication((current) => ({ ...current, [publication.id]: data.shares || [] }));
  }

  async function loadComments(publication: Publication) {
    const data = await api<{ comments?: Comment[] }>(`/api/library/${publication.id}/comments`);
    setCommentsByPublication((current) => ({ ...current, [publication.id]: data.comments || [] }));
  }

  async function loadAbuseCases() {
    const data = await api<{ abuse_reports?: AbuseCase[] }>("/api/abuse-reports");
    setAbuseCases(data.abuse_reports || []);
  }

  async function sendMagicLink(email = signupEmail) {
    if (!email.trim()) return;
    const data = await api<Record<string, string>>("/api/ai/signup", {
      method: "POST",
      body: JSON.stringify({ email, name: email.split("@")[0], agent: "htmlshare-ui", intent: "publish-html-files" })
    });
    setNotice(data.dev_magic_url ? `Magic link sent. Dev link: ${data.dev_magic_url}` : "Magic link sent.");
  }

  async function handleGoogleCredential(credential: string) {
    await api<Session>("/auth/google/id-token", {
      method: "POST",
      body: JSON.stringify({ credential })
    });
    await refreshSession();
  }

  async function createKey() {
    const data = await api<{ api_key: string }>("/api/api-keys", {
      method: "POST",
      body: JSON.stringify({ name: "Claude / Cowork publishing key" })
    });
    setApiKey(data.api_key);
    setNotice("Agent key created. Store it now; it will not be shown again.");
  }

  async function publishPublication() {
    if (!draft.files.length) {
      setNotice("Select at least one file before publishing.");
      return;
    }
    const recipients = draft.visibility === "recipients" || draft.visibility === "signed"
      ? draft.recipients
        .split(/[;,]/)
        .map((email) => email.trim())
        .filter(Boolean)
      : [];
    if ((draft.visibility === "recipients" || draft.visibility === "signed") && recipients.length === 0) {
      setNotice("Add at least one email or domain before publishing with restricted access.");
      return;
    }
    if (draft.visibility === "signed" && recipients.some((target) => target.startsWith("@"))) {
      setNotice("Signed access requires specific email addresses, not domains.");
      return;
    }
    const title = draft.title.trim() || "Untitled file";
    const uploadedFiles = draft.files.reduce<Record<string, string>>((files, file) => {
      files[file.name] = file.content;
      return files;
    }, {});
    const data = await api<{ id: string; url: string; slug: string }>("/api/publish", {
      method: "POST",
      body: JSON.stringify({
        mode: "registered",
        title,
        visibility: draft.visibility,
        require_registration: draft.visibility === "recipients" || draft.visibility === "signed",
        files: uploadedFiles,
        share: draft.visibility === "recipients" ? {
          emails: recipients,
          message: `Here is ${title}.`
        } : undefined
      })
    });
    if (draft.visibility === "signed") {
      await Promise.all(recipients.map((email) => api(`/api/library/${data.id}/signed-access`, {
        method: "POST",
        body: JSON.stringify({ email, message: `Please open this signed access link for ${title}.` })
      })));
    }
    setNotice(`File published: ${data.url}`);
    await refreshPublications();
    setSelectedId(data.id);
    setActive("Library");
  }

  async function shareSelected() {
    if (!selected || !shareEmail.trim()) return;
    const recipients = shareEmail
      .split(/[;,]/)
      .map((email) => email.trim())
      .filter(Boolean);
    await api("/api/share", {
      method: "POST",
      body: JSON.stringify({ id: selected.id, emails: recipients, message: `Shared from htmlshare: ${selected.title}` })
    });
    setShareEmail("");
    setNotice("Share email sent.");
    await loadShares(selected);
  }

  async function sendSignedAccess() {
    if (!selected || !signedAccessEmail.trim()) return;
    await api(`/api/library/${selected.id}/signed-access`, {
      method: "POST",
      body: JSON.stringify({
        email: signedAccessEmail.trim(),
        message: `Signed access requested for legal proof: ${selected.title}`
      })
    });
    setSignedAccessEmail("");
    setNotice("Signed access token emailed.");
  }

  async function replyToComment(commentId: string) {
    if (!selected || !replyBody.trim()) return;
    await api(`/api/library/${selected.id}/comments`, {
      method: "POST",
      body: JSON.stringify({ parent_id: commentId, body: replyBody.trim(), scope: "general" })
    });
    setReplyTo("");
    setReplyBody("");
    await loadComments(selected);
  }

  async function archiveComment(commentId: string, archived: boolean) {
    if (!selected) return;
    await api(`/api/comments/${commentId}`, {
      method: "PATCH",
      body: JSON.stringify({ archived })
    });
    await loadComments(selected);
  }

  async function deleteComment(commentId: string) {
    if (!selected) return;
    await api(`/api/comments/${commentId}`, { method: "DELETE" });
    await loadComments(selected);
  }

  async function updateSelectedAccess(visibility: string) {
    if (!selected) return;
    await api(`/api/library/${selected.id}`, {
      method: "PATCH",
      body: JSON.stringify({ visibility, require_registration: visibility === "recipients" || visibility === "signed" })
    });
    setNotice(`Access updated to ${visibility}.`);
    await refreshPublications();
  }

  async function updateSelectedTitle(title: string) {
    if (!selected) return;
    await api(`/api/library/${selected.id}`, {
      method: "PATCH",
      body: JSON.stringify({ title })
    });
    setNotice("File title updated.");
    await refreshPublications();
  }

  async function copyHelpLink() {
    await navigator.clipboard.writeText(llmsHelpUrl);
    setNotice(`Help link copied. Paste ${llmsHelpUrl} into your LLM and ask how to use htmlshare.`);
  }

  async function copyApiKey() {
    if (!apiKey) return;
    await navigator.clipboard.writeText(apiKey);
    setNotice("Agent key copied.");
  }

  async function logout() {
    await api<{ ok: boolean }>("/api/session", { method: "DELETE" });
    setSession({ user: null });
    setPublications([]);
    setSelectedId("");
    setApiKey("");
    setNotice("Signed out.");
  }

  if (!session.user) {
    return (
      <Onboarding
        signupEmail={signupEmail}
        setSignupEmail={setSignupEmail}
        sendMagicLink={sendMagicLink}
        googleClientId={googleClientId}
        onGoogleCredential={handleGoogleCredential}
        notice={notice}
      />
    );
  }

  return (
    <div className="app-shell">
      <Sidebar active={active} setActive={setActive} user={session.user} queued={publications.length} onLogout={logout} />
      <div className="main-column">
        <TopBar active={active} user={session.user} onHelp={copyHelpLink} />
        <main className="workspace">
          {notice && (
            <div className="notice">
              <Sparkles size={14} />
              <span>{notice}</span>
              <button onClick={() => setNotice("")}>Dismiss</button>
            </div>
          )}

          {active === "Library" && (
            selected ? (
              <LibraryView
                publications={publications}
                selected={selected}
                statsByPublication={statsByPublication}
                totalVisits={totalVisits}
                onSelect={(publication) => setSelectedId(publication.id)}
                publishPublication={publishPublication}
                shareEmail={shareEmail}
                setShareEmail={setShareEmail}
                shareSelected={shareSelected}
                signedAccessEmail={signedAccessEmail}
                setSignedAccessEmail={setSignedAccessEmail}
                sendSignedAccess={sendSignedAccess}
                shares={sharesByPublication[selected.id] || []}
                updateSelectedAccess={updateSelectedAccess}
                updateSelectedTitle={updateSelectedTitle}
              />
            ) : (
              <EmptyLibrary draft={draft} setDraft={setDraft} publishPublication={publishPublication} />
            )
          )}

          {active === "History" && <HistoryView history={history} />}
          {active === "Shared with me" && <SharedWithMeView publications={sharedWithMe} />}
          {active === "Bookmarks" && <BookmarksView bookmarks={bookmarks} reload={loadBookmarks} />}
          {active === "Recipients" && <RecipientsView publications={publications} statsByPublication={statsByPublication} sharesByPublication={sharesByPublication} />}
          {active === "Agent keys" && <AgentKeysView apiKey={apiKey} createKey={createKey} copyApiKey={copyApiKey} />}
          {active === "Activity" && <ActivityView statsByPublication={statsByPublication} abuseCases={abuseCases} />}
          {active === "Settings" && <SettingsView user={session.user} sendMagicLink={sendMagicLink} />}
        </main>
      </div>
    </div>
  );
}

function Onboarding({
  signupEmail,
  setSignupEmail,
  sendMagicLink,
  googleClientId,
  onGoogleCredential,
  notice
}: {
  signupEmail: string;
  setSignupEmail: (value: string) => void;
  sendMagicLink: () => void;
  googleClientId: string;
  onGoogleCredential: (credential: string) => void;
  notice: string;
}) {
  const googleButtonRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!googleClientId || !googleButtonRef.current) return;
    let cancelled = false;
    loadGoogleIdentityScript().then(() => {
      if (cancelled || !googleButtonRef.current) return;
      const google = (window as any).google;
      if (!google?.accounts?.id) return;
      google.accounts.id.initialize({
        client_id: googleClientId,
        callback: (response: { credential?: string }) => {
          if (response.credential) {
            void onGoogleCredential(response.credential);
          }
        }
      });
      google.accounts.id.renderButton(googleButtonRef.current, {
        type: "standard",
        theme: "outline",
        size: "large",
        text: "continue_with",
        width: 360
      });
    });
    return () => {
      cancelled = true;
    };
  }, [googleClientId, onGoogleCredential]);

  return (
    <main className="onboarding">
      <section className="onboarding-copy">
        <Brand />
        <div className="statement">
          <p className="eyebrow">Console · v1</p>
          <h1>
            Where <span className="agent-highlight">agents</span> publish
            <span className="muted-line"> for humans.</span>
          </h1>
          <p>
            Claude assembles the file. You curate who reads it. The recipient opens a quiet, well-set page, not a SaaS dashboard.
          </p>
          <div className="steps">
            <Step number="ONE">An agent POSTs an HTML bundle to your endpoint.</Step>
            <Step number="TWO">You choose who can read it and how they prove it.</Step>
            <Step number="THREE">The recipient gets a link. Nothing else moves.</Step>
          </div>
        </div>
        <div className="footnote">
          <span>Metrica Uno · 2026</span>
        </div>
      </section>
      <section className="auth-panel">
        <div className="auth-card">
          <div>
            <p className="eyebrow">Sign in</p>
            <h2>Open the console.</h2>
            <p>Use Google or a single-use email link. Comments remain disabled in this version.</p>
          </div>
          {googleClientId ? (
            <div className="google-button-slot" ref={googleButtonRef} />
          ) : (
            <a className="oauth-button" href="/auth/google">
              <span className="google-dot" />
              Continue with Google
              <ArrowRight size={15} />
            </a>
          )}
          <div className="divider">
            <span />
            <b>OR · EMAIL LINK</b>
            <span />
          </div>
          <label className="field">
            <span>Work email</span>
            <div>
              <Mail size={16} />
              <input value={signupEmail} onChange={(event) => setSignupEmail(event.target.value)} placeholder="you@company.com" />
              <button onClick={() => sendMagicLink()}>
                Send
                <ArrowRight size={15} />
              </button>
            </div>
          </label>
          <div className="agent-note">
            <KeyRound size={15} />
            <div>
              <b>AI-first publishing</b>
              <p><a href="/llms.txt">AI Instructions here</a></p>
            </div>
          </div>
          <a className="help-link" href="/llms.txt">
            <CircleHelp size={15} />
            Help: paste this link in your LLM and ask
          </a>
          {notice && <pre className="notice-text">{notice}</pre>}
        </div>
      </section>
    </main>
  );
}

function LibraryView(props: {
  publications: Publication[];
  selected: Publication;
  statsByPublication: Record<string, Stats>;
  totalVisits: number;
  onSelect: (publication: Publication) => void;
  publishPublication: () => void;
  shareEmail: string;
  setShareEmail: (value: string) => void;
  shareSelected: () => void;
  signedAccessEmail: string;
  setSignedAccessEmail: (value: string) => void;
  sendSignedAccess: () => void;
  shares: Share[];
  updateSelectedAccess: (visibility: string) => void;
  updateSelectedTitle: (title: string) => Promise<void>;
}) {
  const {
    publications,
    selected,
    statsByPublication,
    totalVisits,
    onSelect,
    publishPublication,
    shareEmail,
    setShareEmail,
    shareSelected,
    signedAccessEmail,
    setSignedAccessEmail,
    sendSignedAccess,
    shares,
    updateSelectedAccess,
    updateSelectedTitle
  } = props;
  const selectedStats = statsByPublication[selected.id] || { visits: 0, logs: [] };
  const [editingTitle, setEditingTitle] = useState(false);
  const [titleDraft, setTitleDraft] = useState(selected.title);

  useEffect(() => {
    setTitleDraft(selected.title);
    setEditingTitle(false);
  }, [selected.id, selected.title]);

  async function saveTitle() {
    if (!titleDraft.trim()) return;
    await updateSelectedTitle(titleDraft.trim());
    setEditingTitle(false);
  }

  return (
    <div className="library-layout">
      <section className="library-main">
        <div className="hero-row">
          <div>
            <p className="eyebrow">Library · {publications.length} files</p>
            <h1>
              Your shared files
              <span> published by agents.</span>
            </h1>
          </div>
          <div className="hero-actions">
            <button className="button secondary">
              <KeyRound size={15} />
              Agent keys
            </button>
            <button className="button primary" onClick={publishPublication}>
              <Plus size={15} />
              New file
            </button>
          </div>
        </div>

        <div className="toolbar">
          <div className="search">
            <Search size={15} />
            <span>Search files, recipients, agents...</span>
            <kbd>⌘ K</kbd>
          </div>
          <Filter label="All status" />
          <Filter label="Any access" />
          <Filter label="Last 30 days" />
        </div>

        <PublicationTable publications={publications} statsByPublication={statsByPublication} selected={selected} onSelect={onSelect} />
      </section>

      <aside className="publication-panel">
        <div className="panel-header">
          <p className="eyebrow">File</p>
          <div className="panel-title-row">
            <h2>{selected.title}</h2>
            <button type="button" onClick={() => setEditingTitle((current) => !current)}>
              Edit
            </button>
          </div>
          <span>{selected.visibility} · {selected.files.length} files</span>
        </div>
        {editingTitle && (
          <label className="compact-field">
            <span>Title</span>
            <div>
              <input value={titleDraft} onChange={(event) => setTitleDraft(event.target.value)} />
              <button onClick={saveTitle}>
                <Check size={14} />
              </button>
            </div>
          </label>
        )}
        <div className="metric-grid">
          <Metric label="Visits" value={String(selectedStats.visits)} note="tracked requests" />
          <Metric label="Total reach" value={String(totalVisits)} note="all files" />
        </div>
        <div className="access-box">
          <div>
            <Globe size={16} />
            <b>Public URL</b>
          </div>
          <code>{window.location.origin}/f/{selected.slug}/</code>
          <div className="inline-actions">
            <button onClick={() => navigator.clipboard.writeText(`${window.location.origin}/f/${selected.slug}/`)}>
              <Copy size={14} />
              Copy
            </button>
            <a href={`/f/${selected.slug}/`} target="_blank">
              <Eye size={14} />
              Open
            </a>
          </div>
        </div>
        <div className="access-modes">
          {["private", "recipients", "signed", "public"].map((mode) => (
            <button key={mode} className={selected.visibility === mode ? "selected" : ""} onClick={() => updateSelectedAccess(mode)}>
              {mode === "public" ? <Globe size={14} /> : mode === "private" ? <Lock size={14} /> : mode === "signed" ? <Check size={14} /> : <Mail size={14} />}
              <span>{accessLabel(mode)}</span>
            </button>
          ))}
        </div>
        <label className="compact-field">
          <span>Share by email or domain</span>
          <div>
            <input value={shareEmail} onChange={(event) => setShareEmail(event.target.value)} placeholder="reader@example.com, @example.com" />
            <button onClick={shareSelected}>
              <Share2 size={14} />
            </button>
          </div>
        </label>
        <label className="compact-field">
          <span>Signed legal access</span>
          <div>
            <input value={signedAccessEmail} onChange={(event) => setSignedAccessEmail(event.target.value)} placeholder="legal@example.com" />
            <button onClick={sendSignedAccess}>
              <Mail size={14} />
            </button>
          </div>
        </label>
        <div className="mini-list">
          <p className="eyebrow">Recipients · {shares.length}</p>
          {shares.slice(0, 4).map((share) => (
            <span key={share.id}>{share.email}</span>
          ))}
          {!shares.length && <small>No recipients shared yet.</small>}
        </div>
        <div className="mini-list">
          <p className="eyebrow">Signed proofs · {selectedStats.signed_proofs?.length || 0}</p>
          {selectedStats.signed_proofs?.slice(0, 4).map((proof) => (
            <span key={proof.id}>{proof.email} · {formatDate(proof.created_at)}</span>
          ))}
          {!selectedStats.signed_proofs?.length && <small>No signed access proofs yet.</small>}
        </div>
      </aside>
    </div>
  );
}

function CommentInbox({
  comments,
  replyTo,
  setReplyTo,
  replyBody,
  setReplyBody,
  replyToComment,
  archiveComment,
  deleteComment
}: {
  comments: Comment[];
  replyTo: string;
  setReplyTo: (value: string) => void;
  replyBody: string;
  setReplyBody: (value: string) => void;
  replyToComment: (commentId: string) => void;
  archiveComment: (commentId: string, archived: boolean) => void;
  deleteComment: (commentId: string) => void;
}) {
  const roots = comments.filter((comment) => !comment.parent_id);
  return (
    <div className="comment-inbox">
      <p className="eyebrow">Comments · {comments.length}</p>
      {roots.length ? roots.slice(0, 5).map((comment) => (
        <div className="comment-card" key={comment.id}>
          <div>
            <Pill tone={comment.scope === "inline" ? "purple" : "outline"}>{comment.scope}</Pill>
            <time>{formatDate(comment.created_at)}</time>
          </div>
          {comment.anchor_text && <blockquote>{comment.anchor_text}</blockquote>}
          <p>{comment.body}</p>
          <small>{comment.email || "Signed viewer"}</small>
          {comments.filter((reply) => reply.parent_id === comment.id).map((reply) => (
            <div className="comment-reply" key={reply.id}>
              <b>{reply.email || "Owner"}</b>
              <span>{reply.body}</span>
            </div>
          ))}
          {replyTo === comment.id ? (
            <div className="reply-box">
              <textarea value={replyBody} onChange={(event) => setReplyBody(event.target.value)} placeholder="Reply to this comment" />
              <button onClick={() => replyToComment(comment.id)}>
                <Send size={14} />
                Reply
              </button>
            </div>
          ) : (
            <div className="comment-actions">
              <button onClick={() => setReplyTo(comment.id)}>Reply</button>
              <button onClick={() => archiveComment(comment.id, !comment.archived_at)}>{comment.archived_at ? "Unarchive" : "Archive"}</button>
              <button onClick={() => deleteComment(comment.id)}>Delete</button>
            </div>
          )}
        </div>
      )) : <small>No comments yet.</small>}
    </div>
  );
}

function EmptyLibrary({ draft, setDraft, publishPublication }: PublishComposerProps) {
  return (
    <div className="empty-state">
      <p className="eyebrow">Library · empty</p>
      <h1>
        Publish the first
        <span> agent file.</span>
      </h1>
      <PublishComposer draft={draft} setDraft={setDraft} publishPublication={publishPublication} />
    </div>
  );
}

function PublicationTable({
  publications,
  statsByPublication,
  selected,
  onSelect
}: {
  publications: Publication[];
  statsByPublication: Record<string, Stats>;
  selected: Publication;
  onSelect: (publication: Publication) => void;
}) {
  return (
    <div className="publication-table">
      <div className="table-head">
        <span>File</span>
        <span>Published</span>
        <span>Access</span>
        <span>Visits</span>
        <span />
      </div>
      {publications.map((publication) => (
        <button key={publication.id} className={`publication-row ${selected.id === publication.id ? "selected" : ""}`} onClick={() => onSelect(publication)}>
          <span>
            <b>{publication.title}</b>
            <small>{publication.files.join(" · ") || "index.html"}</small>
          </span>
          <time>{formatDate(publication.created_at)}</time>
          <Pill tone={publication.visibility === "public" ? "outline" : "purple"}>{publication.visibility}</Pill>
          <span>{statsByPublication[publication.id]?.visits || 0}</span>
          <MoreHorizontal size={16} />
        </button>
      ))}
    </div>
  );
}

function PublishComposer({
  draft,
  setDraft,
  publishPublication
}: PublishComposerProps) {
  async function handleFileSelection(event: React.ChangeEvent<HTMLInputElement>) {
    const selectedFiles = Array.from(event.target.files || []);
    const files = await Promise.all(
      selectedFiles.map(async (file) => ({
        name: file.webkitRelativePath || file.name,
        content: await file.text(),
        size: file.size
      }))
    );
    setDraft((current) => ({ ...current, files }));
  }

  return (
    <div className="composer">
      <div>
        <p className="eyebrow">One-call publish</p>
        <h3>POST-compatible file bundle</h3>
      </div>
      <label className="file-picker">
        <input
          type="file"
          multiple
          accept=".html,.htm,.css,.js,.json,.txt,.svg,.md,.xml,.csv"
          onChange={handleFileSelection}
        />
        <span>
          <Upload size={15} />
          Select files
        </span>
        <small>
          {draft.files.length
            ? `${draft.files.length} file${draft.files.length === 1 ? "" : "s"} selected`
            : "Select one or more HTML, CSS or JS files."}
        </small>
      </label>
      {draft.files.length > 0 && (
        <div className="file-list">
          {draft.files.map((file) => (
            <span key={file.name}>
              <FileText size={14} />
              <b>{file.name}</b>
              <small>{formatBytes(file.size)}</small>
            </span>
          ))}
        </div>
      )}
      <input value={draft.title} onChange={(event) => setDraft((current) => ({ ...current, title: event.target.value }))} placeholder="Title for this shared file" />
      <select value={draft.visibility} onChange={(event) => setDraft((current) => ({ ...current, visibility: event.target.value }))}>
        <option value="private">Private</option>
        <option value="recipients">Recipients (emails or domains)</option>
        <option value="signed">Signed access (email proof)</option>
        <option value="public">Link access</option>
      </select>
      <small className="visibility-help">{visibilityHelp[draft.visibility]}</small>
      {(draft.visibility === "recipients" || draft.visibility === "signed") && (
        <input value={draft.recipients} onChange={(event) => setDraft((current) => ({ ...current, recipients: event.target.value }))} placeholder={draft.visibility === "signed" ? "legal@example.com, reviewer@example.com" : "reader@example.com, team@example.com, @example.com"} />
      )}
      <button className="button primary" onClick={publishPublication}>
        <Send size={15} />
        Publish files
      </button>
    </div>
  );
}

function RecipientsView({
	publications,
	statsByPublication,
	sharesByPublication
}: {
  publications: Publication[];
  statsByPublication: Record<string, Stats>;
  sharesByPublication: Record<string, Share[]>;
}) {
  const logs = Object.values(statsByPublication).flatMap((stat) => stat.logs || []);
  const sharedEmails = Object.values(sharesByPublication).flatMap((shares) => shares.map((share) => share.email));
  const emails = Array.from(new Set([...sharedEmails, ...logs.map((log) => log.email).filter(Boolean)]));
  return (
    <section className="page-section">
      <PageTitle eyebrow="Recipients" title="People who opened files." muted={`${emails.length} identified readers`} />
      <div className="cards-grid">
        {emails.length ? emails.map((email) => <PersonCard key={email} email={email!} logs={logs.filter((log) => log.email === email)} />) : (
          <div className="blank-card">No identified recipients yet. Share a file by email to populate this view.</div>
        )}
      </div>
      <div className="soft-table">
        {publications.map((publication) => (
          <div key={publication.id}>
            <FileText size={16} />
            <span>{publication.title}</span>
            <b>{statsByPublication[publication.id]?.visits || 0} accesses</b>
          </div>
        ))}
      </div>
    </section>
  );
}

function HistoryView({ history }: { history: HistoryEntry[] }) {
  return (
    <section className="page-section">
      <PageTitle eyebrow="History" title="Pages you opened." muted={`${history.length} recent files`} />
      <div className="soft-table library-list">
        {history.length ? history.map((entry) => (
          <a key={entry.publication.id} href={`/f/${entry.publication.slug}/`} target="_blank">
            <History size={16} />
            <span>{entry.publication.title}</span>
            <small>{entry.path}</small>
            <b>{entry.visits} visits</b>
            <time>{formatDate(entry.last_opened_at)}</time>
          </a>
        )) : <div className="blank-card">No visited pages yet.</div>}
      </div>
    </section>
  );
}

function SharedWithMeView({ publications }: { publications: Publication[] }) {
  return (
    <section className="page-section">
      <PageTitle eyebrow="Shared with me" title="Files you can access." muted={`${publications.length} available files`} />
      <div className="soft-table library-list">
        {publications.length ? publications.map((publication) => (
          <a key={publication.id} href={`/f/${publication.slug}/`} target="_blank">
            <Share2 size={16} />
            <span>{publication.title}</span>
            <small>{publication.visibility}</small>
            <b>{publication.files.length} files</b>
            <time>{formatDate(publication.created_at)}</time>
          </a>
        )) : <div className="blank-card">No files have been shared with this account yet.</div>}
      </div>
    </section>
  );
}

function BookmarksView({ bookmarks, reload }: { bookmarks: BookmarkEntry[]; reload: () => void }) {
  async function remove(publication: Publication) {
    await api(`/api/bookmarks/${publication.id}`, { method: "DELETE" });
    await reload();
  }

  return (
    <section className="page-section">
      <PageTitle eyebrow="Bookmarks" title="Read later." muted={`${bookmarks.length} saved files`} />
      <div className="soft-table library-list">
        {bookmarks.length ? bookmarks.map((entry) => (
          <div key={entry.bookmark.id}>
            <BookMarked size={16} />
            <span>{entry.publication.title}</span>
            <small>{entry.bookmark.kind.replace("_", " ")}</small>
            <a href={`/f/${entry.publication.slug}/`} target="_blank">Open</a>
            <button onClick={() => remove(entry.publication)}>Remove</button>
          </div>
        )) : <div className="blank-card">No bookmarks yet. Use Read later from the page toolbar.</div>}
      </div>
    </section>
  );
}

function AgentKeysView({
  apiKey,
  createKey,
  copyApiKey
}: {
  apiKey: string;
  createKey: () => void;
  copyApiKey: () => void;
}) {
  return (
    <section className="page-section">
      <PageTitle eyebrow="Agent keys" title="Provision keys for Claude, Cowork and MCP." muted="Keys authorize one-call publishing." />
      <div className="agent-grid">
        <div className="agent-card">
          <KeyRound size={22} />
          <h2>Create publishing key</h2>
          <p>Use this as `Authorization: Bearer hsk_...` for `/api/publish` or `HTMLSHARE_TOKEN` for the MCP server.</p>
          <button className="button primary" onClick={createKey}>
            <Plus size={15} />
            Create key
          </button>
          {apiKey && (
            <div className="api-key-result">
              <pre>{apiKey}</pre>
              <button type="button" onClick={copyApiKey} aria-label="Copy agent key">
                <Copy size={15} />
                Copy
              </button>
            </div>
          )}
        </div>
        <div className="code-card">
          <p className="eyebrow">Registered protocol</p>
          <pre>{`POST /api/publish
Authorization: Bearer hsk_...
Content-Type: application/json

{
  "mode": "registered",
  "title": "Board file",
  "visibility": "recipients",
  "files": {
    "index.html": "<!doctype html>..."
  }
}`}</pre>
          <p><a href="/llms.txt">AI Instructions here</a></p>
        </div>
      </div>
    </section>
  );
}

function ActivityView({ statsByPublication, abuseCases }: { statsByPublication: Record<string, Stats>; abuseCases: AbuseCase[] }) {
  const logs = Object.values(statsByPublication)
    .flatMap((stat) => stat.logs || [])
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  const signedProofs = Object.values(statsByPublication)
    .flatMap((stat) => stat.signed_proofs || [])
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  return (
    <section className="page-section">
      <PageTitle eyebrow="Activity" title="Access log." muted="IP, email, path and status are recorded when available." />
      <div className="activity-list">
        {signedProofs.length ? signedProofs.map((proof) => (
          <div key={proof.id}>
            <Check size={15} />
            <span>{proof.email}</span>
            <code>{proof.ip}</code>
            <b>Signed access proof</b>
            <Pill tone="success">signed</Pill>
            <time>{formatDate(proof.created_at)}</time>
          </div>
        )) : <div className="blank-card">No signed access proofs yet.</div>}
      </div>
      <div className="abuse-list">
        {abuseCases.length ? abuseCases.map((publication) => (
          <div key={publication.id}>
            <ShieldAlert size={15} />
            <span>{publication.slug}</span>
            <Pill tone={publication.auto_blocked ? "error" : "purple"}>{publication.severity}</Pill>
            <b>{publication.reason}</b>
            <small>{publication.analysis_summary || publication.status}</small>
          </div>
        )) : <div className="blank-card">No abuse notices yet.</div>}
      </div>
      <div className="activity-list">
        {logs.length ? logs.map((log) => (
          <div key={log.id}>
            <Activity size={15} />
            <span>{log.email || "Anonymous"}</span>
            <code>{log.ip}</code>
            <b>{log.path}</b>
            <Pill tone={log.allowed ? "success" : "error"}>{String(log.status)}</Pill>
            <time>{formatDate(log.created_at)}</time>
          </div>
        )) : <div className="blank-card">No access logs yet.</div>}
      </div>
    </section>
  );
}

function SettingsView({ user, sendMagicLink }: { user: User; sendMagicLink: (email?: string) => void }) {
  return (
    <section className="page-section">
      <PageTitle eyebrow="Settings" title="Workspace and confirmation." muted={user.email} />
      <div className="settings-grid">
        <div className="agent-card">
          <Check size={22} />
          <h2>Email status</h2>
          <p>{user.email_confirmed === "true" ? "Confirmed. Automation is enabled." : "Pending confirmation. Automation is blocked."}</p>
          <button className="button secondary" onClick={() => sendMagicLink(user.email)}>
            <Mail size={15} />
            Resend magic link
          </button>
        </div>
        <div className="agent-card">
          <Clock size={22} />
          <h2>Automatic registration cleanup</h2>
          <p>Unconfirmed AI-created workspaces and their owned content expire after 24 hours.</p>
        </div>
      </div>
    </section>
  );
}

function Sidebar({
  active,
  setActive,
  user,
  queued,
  onLogout
}: {
  active: NavKey;
  setActive: (key: NavKey) => void;
  user: User;
  queued: number;
  onLogout: () => void;
}) {
  return (
    <aside className="sidebar">
      <Brand />
      <nav>
        {navItems.map(({ key, icon: Icon }) => (
          <button key={key} className={active === key ? "active" : ""} onClick={() => setActive(key)}>
            <Icon size={16} />
            {key}
            {key === "Activity" && queued > 0 && <b>{queued}</b>}
          </button>
        ))}
      </nav>
      <div className="user-card">
        <div>{initials(user.email)}</div>
        <span>
          <b>{user.name || user.email.split("@")[0]}</b>
          <small>{user.email}</small>
        </span>
        <button onClick={onLogout} title="Sign out" aria-label="Sign out">
          <LogOut size={15} />
        </button>
      </div>
    </aside>
  );
}

function TopBar({ active, user, onHelp }: { active: NavKey; user: User; onHelp: () => void }) {
  return (
    <header className="topbar">
      <div>
        <span>Metrica Uno</span>
        <span>·</span>
        <b>{active}</b>
      </div>
      <div>
        <button className="help-button" onClick={onHelp} title={`Copy ${llmsHelpUrl}`}>
          <CircleHelp size={14} />
          Help
        </button>
        <Pill tone="default">
          <Sparkles size={12} />
          Agent v0.4
        </Pill>
        <Pill tone={user.email_confirmed === "true" ? "success" : "error"}>{user.email_confirmed === "true" ? "Confirmed" : "Pending"}</Pill>
      </div>
    </header>
  );
}

function Brand() {
  return (
    <a className="brand" href="/">
      <img src={logoMark} alt="" />
      <span><b>html</b><em>share</em></span>
    </a>
  );
}

function PageTitle({ eyebrow, title, muted }: { eyebrow: string; title: string; muted: string }) {
  return (
    <div className="page-title">
      <p className="eyebrow">{eyebrow}</p>
      <h1>{title}</h1>
      <span>{muted}</span>
    </div>
  );
}

function Step({ number, children }: { number: string; children: React.ReactNode }) {
  return (
    <div className="step">
      <span>{number}</span>
      <p>{children}</p>
    </div>
  );
}

function Filter({ label }: { label: string }) {
  return <button className="filter">{label}</button>;
}

function Pill({ tone, children }: { tone: "default" | "purple" | "success" | "error" | "outline"; children: React.ReactNode }) {
  return <span className={`pill ${tone}`}>{children}</span>;
}

function Metric({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <b>{value}</b>
      <small>{note}</small>
    </div>
  );
}

function PersonCard({ email, logs }: { email: string; logs: AccessLog[] }) {
  return (
    <div className="person-card">
      <div>{initials(email)}</div>
      <b>{email}</b>
      <span>{logs.length} accesses</span>
      <small>Last {formatDate(logs[0]?.created_at)}</small>
    </div>
  );
}

async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(init.headers || {})
    }
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

function loadGoogleIdentityScript() {
  const existing = document.querySelector<HTMLScriptElement>('script[src="https://accounts.google.com/gsi/client"]');
  if (existing) {
    return Promise.resolve();
  }
  return new Promise<void>((resolve, reject) => {
    const script = document.createElement("script");
    script.src = "https://accounts.google.com/gsi/client";
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("google identity script failed"));
    document.head.appendChild(script);
  });
}

function formatDate(value?: string) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(new Date(value));
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${Math.round(value / 1024)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function accessLabel(value: string) {
  if (value === "public") return "Link access";
  if (value === "recipients") return "Recipients";
  if (value === "signed") return "Signed access";
  return "Private";
}

function initials(value: string) {
  return value
    .split("@")[0]
    .split(/[.\-_ ]/)
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
}

createRoot(document.getElementById("root")!).render(<App />);
