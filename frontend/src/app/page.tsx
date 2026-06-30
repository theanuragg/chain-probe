"use client";

import { useSearchParams } from "next/navigation";
import { Suspense } from "react";
import LandingPage from "@/components/LandingPage";
import AuditPage from "@/components/AuditPage";
import ReportPage from "@/components/ReportPage";

function PageContent() {
  const searchParams = useSearchParams();
  const page = searchParams.get("page") || "home";

  switch (page) {
    case "audit":
      return <AuditPage />;
    case "report":
      return <ReportPage />;
    default:
      return <LandingPage />;
  }
}

export default function Home() {
  return (
    <Suspense fallback={null}>
      <PageContent />
    </Suspense>
  );
}
