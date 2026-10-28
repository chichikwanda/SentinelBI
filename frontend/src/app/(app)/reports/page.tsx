import { Suspense } from "react";
import { TrafficReport } from "@/components/traffic-report";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function ReportsPage() {
  return (
    <div className="mx-auto max-w-5xl space-y-4">
      <h1 className="text-xl font-semibold print:hidden">Reports</h1>
      <Suspense fallback={<div className="h-48" />}>
        <TrafficReport />
      </Suspense>
      <div className="space-y-4 print:hidden">
        <Card>
          <CardHeader>
            <CardTitle>Security summary (PDF)</CardTitle>
            <a href="/api/proxy/reports/summary.pdf" download>
              <Button size="sm" data-testid="download-pdf">Download PDF</Button>
            </a>
          </CardHeader>
          <CardContent className="text-sm text-black/70 dark:text-white/70">
            Organisation risk, open alerts by severity, the highest-risk open alerts and the top recommended
            actions for each, with the data volume of the busiest hosts. Suitable to hand to management.
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>All alerts (CSV)</CardTitle>
            <a href="/api/proxy/reports/alerts.csv" download>
              <Button size="sm" variant="outline" data-testid="download-csv">Download CSV</Button>
            </a>
          </CardHeader>
          <CardContent className="text-sm text-black/70 dark:text-white/70">
            Every alert for your organisation with severity, risk, status and analyst notes, for your own
            analysis. Free-text cells are escaped so spreadsheets cannot run them as formulas.
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Data volume per host (CSV)</CardTitle>
            <div className="flex gap-2">
              <a href="/api/proxy/reports/traffic.csv?hours=24" download>
                <Button size="sm" variant="outline" data-testid="download-traffic">
                  Last 24 hours
                </Button>
              </a>
              <a href="/api/proxy/reports/traffic.csv?hours=168" download>
                <Button size="sm" variant="outline">
                  Last 7 days
                </Button>
              </a>
            </div>
          </CardHeader>
          <CardContent className="text-sm text-black/70 dark:text-white/70">
            How much each monitored host sent and received, in bytes as the network carried them (IP headers
            included), with flow counts and when it was last seen. Registered addresses with no traffic are
            listed with zeros. The report builder above has the same table, and also who each host talked to,
            what it used and its volume over time. Decimal units: 1 kB is 1000 bytes.
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
