import type { ReactNode } from "react";

interface SectionCardProps {
  title: string;
  copy?: string;
  children: ReactNode;
  aside?: ReactNode;
}

export function SectionCard({ title, copy, children, aside }: SectionCardProps) {
  return (
    <section className="section-card">
      <header className="section-card-header">
        <div>
          <h3>{title}</h3>
          {copy && <p>{copy}</p>}
        </div>
        {aside}
      </header>
      {children}
    </section>
  );
}
