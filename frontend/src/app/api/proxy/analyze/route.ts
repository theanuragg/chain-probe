import { NextRequest, NextResponse } from 'next/server';

const BACKEND_URL = process.env.BACKEND_API_URL;
const BACKEND_API_KEY = process.env.BACKEND_API_KEY;

export async function POST(request: NextRequest) {
  if (!BACKEND_URL) {
    return NextResponse.json(
      { error: 'Backend API URL not configured' },
      { status: 500 }
    );
  }

  try {
    const body = await request.json();
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (BACKEND_API_KEY) {
      headers['x-api-key'] = BACKEND_API_KEY;
    }

    const response = await fetch(`${BACKEND_URL}/analyze`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: response.statusText }));
      return NextResponse.json(error, { status: response.status });
    }

    const data = await response.json();
    return NextResponse.json(data);
  } catch (error) {
    console.error('Proxy error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
