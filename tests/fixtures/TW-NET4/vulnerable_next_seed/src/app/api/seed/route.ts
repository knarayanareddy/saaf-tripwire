import { NextResponse } from "next/server";
import { seedAll } from "@/lib/persist";

export async function GET() {
  const result = await seedAll();
  return NextResponse.json(result);
}
