"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";
import { askQuestion, QueryData } from "../api/rag";

export default function AskPage() {
  const [question, setQuestion] = useState("");
  const [data, setData] = useState<QueryData | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError("");
    setData(null);
    try {
      setData((await askQuestion(question)).data);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "We couldn't search the knowledge base right now.");
    } finally {
      setLoading(false);
    }
  }

  return <main className="shell"><aside><div className="brand">RAGFort</div><nav aria-label="Primary navigation"><Link className="active" href="/">Ask</Link><Link href="/documents">Documents</Link>{["Security", "Activity", "Tests"].map((item) => <button className="future" key={item} type="button" disabled>{item}<small>Future phase</small></button>)}</nav><button className="future settings" type="button" disabled>Settings<small>Future phase</small></button></aside><section className="content"><p className="eyebrow">Development corpus</p><h1>Ask your knowledge base</h1><p className="intro">Search organizational information and receive answers grounded in sources.</p><form onSubmit={submit}><label htmlFor="question">What would you like to know?</label><textarea id="question" value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="Ask a question..." maxLength={2000} required /><button className="ask" disabled={loading || !question.trim()}>{loading ? "Finding information..." : "Ask →"}</button></form>{loading && <p className="progress" aria-live="polite">Finding relevant information... Searching documents · Preparing context · Generating grounded answer</p>}{error && <section className="panel error" role="alert"><h2>We couldn&apos;t search the knowledge base right now.</h2><p>Your request was not answered without supporting documents. Try again shortly.</p></section>}{data?.answer_status === "insufficient_context" && <section className="panel"><h2>We couldn&apos;t find enough information to answer this reliably.</h2><p>Try asking differently or check whether the information exists in the knowledge base.</p></section>}{data?.answer_status === "grounded" && <section className="panel answer"><h2>Answer</h2><p>{data.answer}</p><h2>Sources</h2><div className="sources">{data.sources.map((source) => <article key={source.chunk_id}><strong>{source.title}</strong><span>{source.section ?? source.source}</span></article>)}</div><p className="grounded">Grounded in {data.sources.length} source{data.sources.length === 1 ? "" : "s"}</p></section>}</section></main>;
}
