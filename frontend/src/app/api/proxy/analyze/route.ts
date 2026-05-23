import { NextRequest, NextResponse } from 'next/server';

const BACKEND_URL = process.env.BACKEND_API_URL || 'http://68.183.103.58:3001/api';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    const response = await fetch(`${BACKEND_URL}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
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
