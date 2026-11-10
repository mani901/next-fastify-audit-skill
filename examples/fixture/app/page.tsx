// Fixture: intentionally vulnerable Next.js page.
// Planted issues: dangerouslySetInnerHTML (SEC-002), raw <img> tag (PERF-001).

export default async function HomePage({ searchParams }) {
  const query = (await searchParams)?.q ?? '';
  const res = await fetch('https://api.example.com/search?q=' + query);
  const data = await res.json();

  return (
    <main>
      <h1>Search results for {query}</h1>
      {/* Untrusted HTML from the API is injected directly into the page. */}
      <div dangerouslySetInnerHTML={{ __html: data.html }} />
      <img src="/hero.jpg" alt="Hero" />
    </main>
  );
}
