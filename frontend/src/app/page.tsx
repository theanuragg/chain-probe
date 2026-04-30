"use client";

import LandingPage from "@/components/LandingPage";
import AuditPage from "@/components/AuditPage";
import ReportPage from "@/components/ReportPage";

export default function Home({ searchParams }: { searchParams: { page?: string; data?: string } }) {
  const page = searchParams.page || "home";
  
  switch (page) {
    case "audit":
      return <AuditPage />;
    case "report":
      return <ReportPage />;
    default:
      return <LandingPage />;
  }
}