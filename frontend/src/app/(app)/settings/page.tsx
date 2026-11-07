"use client";

import { useState } from "react";
import { HealthPanel } from "@/components/settings/health-panel";
import { BackupsPanel } from "@/components/settings/backups-panel";
import { RulesPanel } from "@/components/settings/rules-panel";
import { SettingsForm } from "@/components/settings/settings-form";
import { TrainingPanel } from "@/components/settings/training-panel";
import { UsersPanel } from "@/components/settings/users-panel";
import { Button } from "@/components/ui/button";

// Each tab is one place where something that used to need a terminal can now be done.
const TABS: { id: string; label: string; render: () => React.ReactNode }[] = [
  { id: "health", label: "System health", render: () => <HealthPanel /> },
  { id: "alerting", label: "Alerting and risk", render: () => <SettingsForm groups={["Alerting", "Risk"]} /> },
  {
    id: "baseline",
    label: "Baseline and quarantine",
    render: () => <SettingsForm groups={["Baseline and quarantine"]} />,
  },
  { id: "privacy", label: "Privacy and retention", render: () => <SettingsForm groups={["Privacy and retention"]} /> },
  { id: "training", label: "Model training", render: () => <TrainingPanel /> },
  { id: "rules", label: "Rules", render: () => <RulesPanel /> },
  { id: "backups", label: "Backups", render: () => <BackupsPanel /> },
  { id: "access", label: "Access", render: () => <SettingsForm groups={["Access"]} /> },
  { id: "users", label: "People", render: () => <UsersPanel /> },
];

export default function SettingsPage() {
  const [tab, setTab] = useState(TABS[0].id);
  const current = TABS.find((t) => t.id === tab) ?? TABS[0];
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Settings</h1>
      <div className="flex flex-wrap gap-1" role="tablist" aria-label="Settings sections">
        {TABS.map((t) => (
          <Button
            key={t.id}
            size="sm"
            role="tab"
            aria-selected={tab === t.id}
            variant={tab === t.id ? "default" : "outline"}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </Button>
        ))}
      </div>
      <div role="tabpanel">{current.render()}</div>
    </div>
  );
}
