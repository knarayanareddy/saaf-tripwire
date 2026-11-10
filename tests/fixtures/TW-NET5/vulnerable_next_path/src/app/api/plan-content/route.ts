import { NextRequest, NextResponse } from "next/server";
export async function GET(request: NextRequest) {
  const slug = request.nextUrl.searchParams.get("slug");
  const path = `plans/${slug}.md`;
  const res = await fetch(`https://api.github.com/repos/org/repo/contents/${path}`, {
    headers: { Authorization: `Bearer ${process.env.GITHUB_PAT}` },
  });
  return new NextResponse(await res.text());
}
