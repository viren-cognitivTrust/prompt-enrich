import React, { useEffect, useState } from "react";

import { useAuth } from "../auth/AuthContext";
import type { Item } from "../../api/items";
import { createItem, deleteItem, listItems } from "../../api/items";

const DashboardPage: React.FC = () => {
  const { user, logout } = useAuth();
  const [items, setItems] = useState<Item[]>([]);
  const [loading, setLoading] = useState(true);
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const data = await listItems();
        if (mounted) setItems(data);
      } finally {
        if (mounted) setLoading(false);
      }
    })();
    return () => {
      mounted = false;
    };
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;
    setSubmitting(true);
    try {
      const item = await createItem({ title: title.trim(), content: content.trim() || undefined });
      setItems((prev) => [item, ...prev]);
      setTitle("");
      setContent("");
    } catch {
      alert("Failed to create item.");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Delete this item?")) return;
    try {
      await deleteItem(id);
      setItems((prev) => prev.filter((i) => i.id !== id));
    } catch {
      alert("Failed to delete item.");
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur">
        <div className="max-w-5xl mx-auto px-4 py-4 flex items-center justify-between">
          <h1 className="text-xl font-semibold">SecureApp</h1>
          <div className="flex items-center gap-4 text-sm">
            <div className="text-slate-300">
              <div>{user?.email_masked}</div>
              <div className="text-xs uppercase tracking-wide text-slate-400">{user?.role}</div>
            </div>
            <button
              type="button"
              onClick={logout}
              className="rounded-md border border-slate-600 px-3 py-1 text-sm hover:bg-slate-800"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="max-w-5xl mx-auto px-4 py-8">
        <section className="mb-8">
          <h2 className="text-lg font-semibold mb-4">Create secure note</h2>
          <form onSubmit={handleCreate} className="space-y-3 bg-slate-900/80 border border-slate-800 rounded-xl p-4">
            <div>
              <label className="block text-sm font-medium mb-1" htmlFor="title">
                Title
              </label>
              <input
                id="title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1" htmlFor="content">
                Content (optional)
              </label>
              <textarea
                id="content"
                value={content}
                onChange={(e) => setContent(e.target.value)}
                className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 h-24"
              />
              <p className="mt-1 text-xs text-slate-400">
                HTML is sanitized on the server to prevent XSS. Only basic formatting is allowed.
              </p>
            </div>
            <button
              type="submit"
              disabled={submitting}
              className="rounded-md bg-sky-600 hover:bg-sky-500 disabled:opacity-60 px-4 py-2 text-sm font-semibold"
            >
              {submitting ? "Saving..." : "Save note"}
            </button>
          </form>
        </section>

        <section>
          <h2 className="text-lg font-semibold mb-4">Your notes</h2>
          {loading ? (
            <p className="text-sm text-slate-400">Loading...</p>
          ) : items.length === 0 ? (
            <p className="text-sm text-slate-400">No items yet.</p>
          ) : (
            <ul className="space-y-3">
              {items.map((item) => (
                <li
                  key={item.id}
                  className="border border-slate-800 bg-slate-900/80 rounded-xl p-4 flex items-start justify-between gap-4"
                >
                  <div>
                    <h3 className="font-semibold">{item.title}</h3>
                    {item.content && <p className="mt-1 text-sm text-slate-300 break-words">{item.content}</p>}
                    <p className="mt-2 text-xs text-slate-500">
                      Created: {new Date(item.created_at).toLocaleString()}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => void handleDelete(item.id)}
                    className="text-xs rounded-md border border-red-500/70 text-red-300 px-3 py-1 hover:bg-red-500/10"
                  >
                    Delete
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      </main>
    </div>
  );
};

export default DashboardPage;


