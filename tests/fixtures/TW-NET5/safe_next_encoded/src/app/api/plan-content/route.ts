import { NextRequest, NextResponse } from "next/server";
export async function GET(request: NextRequest) {
  const slug = request.nextUrl.searchParams.get("slug");
  if (!slug || !/^[a-z0-9-]+$/.test(slug)) return NextResponse.json({ error: "bad slug" }, { status: 400 });
  const res = await fetch(`https://api.github.com/repos/org/repo/contents/plans/${encodeURIComponent(slug)}.md`);
  return new NextResponse(await res.text());
}
