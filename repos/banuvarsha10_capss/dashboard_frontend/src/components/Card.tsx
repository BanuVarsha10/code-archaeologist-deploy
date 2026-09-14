import type { CSSProperties, ReactNode } from "react";

export function Card({
  title,
  children,
  raised = false,
  className = "",
  style,
}: {
  title?: string;
  children: ReactNode;
  raised?: boolean;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <div className={`card ${raised ? "card-raised" : ""} ${className}`} style={style}>
      {title && <div className="card-title">{title}</div>}
      {children}
    </div>
  );
}
