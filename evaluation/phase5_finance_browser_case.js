// Playwright CLI run-code body. Requires a real Finance Reader OIDC/PKCE session.
// Captures only the safe identity contract and response/citation metadata.
async (page) => {
  const identity = async () => page.evaluate(async () => {
    const response = await fetch("http://localhost:8000/api/v1/me", {credentials: "include"});
    const body = await response.json();
    return body.data;
  });
  const before = await identity();
  if (before?.tenant_id !== "tenant_acme" || !before.roles?.includes("finance_reader")) {
    throw new Error("Browser session is not the canonical ACME Finance Reader");
  }

  await page.getByRole("textbox", {name: "What would you like to know?"})
    .fill("What is the restricted ACME Finance marker FINANCE-ORCHID-815?");
  const responsePromise = page.waitForResponse(r =>
    r.url().endsWith("/api/v1/query") && r.request().method() === "POST");
  await page.getByRole("button", {name: /^Ask/}).click();
  const response = await responsePromise;
  const body = await response.json();
  const sources = body.data?.sources || [];
  const sourceDocs = sources.map(source => source.document_id);
  const authorizedDocuments = new Set(["p5_finance_control", "p5_acme_control"]);
  const passed = response.status() === 200 &&
    body.data?.answer_status === "grounded" &&
    body.data?.answer?.includes("FINANCE-ORCHID-815") &&
    sourceDocs.includes("p5_finance_control") &&
    sourceDocs.every(id => authorizedDocuments.has(id));
  if (!passed) throw new Error(JSON.stringify({status: response.status(), body, sourceDocs}));

  await page.getByRole("heading", {name: "Answer", exact: true}).waitFor({state: "visible"});
  const after = await identity();
  if (JSON.stringify(before) !== JSON.stringify(after)) {
    throw new Error("Canonical Finance Reader identity changed during retrieval");
  }
  return {
    authentication: "real browser OIDC authorization-code S256 PKCE and HttpOnly session",
    identity: before,
    status: response.status(),
    answer_status: body.data.answer_status,
    marker_returned: true,
    source_document_ids: sourceDocs,
    request_id: body.request_id,
    passed,
  };
}
