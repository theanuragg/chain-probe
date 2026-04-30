import { createContext, useContext, useState, ReactNode } from 'react';
import { AnalysisReport, DiffReport } from '@/types';

interface AppState {
  report: AnalysisReport | null;
  setReport: (r: AnalysisReport | null) => void;
  diffResult: DiffReport | null;
  setDiffResult: (d: DiffReport | null) => void;
  files: Record<string, string>;
  setFiles: (f: Record<string, string>) => void;
  skipped: number;
  setSkipped: (n: number) => void;
}

export const AppContext = createContext<AppState | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [diffResult, setDiffResult] = useState<DiffReport | null>(null);
  const [files, setFiles] = useState<Record<string, string>>({});
  const [skipped, setSkipped] = useState(0);

  return (
    <AppContext.Provider value={{ report, setReport, diffResult, setDiffResult, files, setFiles, skipped, setSkipped }}>
      {children}
    </AppContext.Provider>
  );
}

export function useAppState() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useAppState must be used within AppProvider');
  return ctx;
}