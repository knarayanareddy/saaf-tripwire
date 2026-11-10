import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { resetDatabase } from "@/lib/db";

export async function POST() {
  const session = await getServerSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  return NextResponse.json(await resetDatabase());
}
