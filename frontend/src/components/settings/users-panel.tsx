"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/input";
import { Table, Td, Th } from "@/components/ui/table";
import { api } from "@/lib/client-api";
import type { UserRow } from "@/lib/types";

export function UsersPanel() {
  const qc = useQueryClient();
  const users = useQuery({ queryKey: ["users"], queryFn: () => api<UserRow[]>("users"), retry: false });
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");
  const [error, setError] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () => api<UserRow>("users", { method: "POST", body: JSON.stringify({ email, password, role }) }),
    onSuccess: () => {
      setEmail("");
      setPassword("");
      setError(null);
      qc.invalidateQueries({ queryKey: ["users"] });
    },
    onError: (e: Error) => setError(e.message),
  });
  if (users.error) return <p className="text-sm">Only an organisation administrator can manage people.</p>;
  return (
    <Card>
      <CardHeader>
        <CardTitle>People in your organisation</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <Table>
          <thead>
            <tr>
              <Th>Email</Th>
              <Th>Role</Th>
            </tr>
          </thead>
          <tbody>
            {(users.data ?? []).map((u) => (
              <tr key={u.id}>
                <Td>{u.email}</Td>
                <Td>{u.role}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
        <form
          className="grid gap-3 sm:grid-cols-[1fr_1fr_8rem_auto] sm:items-end"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <div>
            <Label htmlFor="new-email">Email</Label>
            <Input id="new-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div>
            <Label htmlFor="new-pass">Password (12+ characters)</Label>
            <Input
              id="new-pass"
              type="password"
              required
              minLength={12}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <div>
            <Label htmlFor="new-role">Role</Label>
            <Select id="new-role" value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="viewer">viewer</option>
              <option value="analyst">analyst</option>
              <option value="admin">admin</option>
            </Select>
          </div>
          <Button type="submit" disabled={create.isPending}>
            Add person
          </Button>
        </form>
        {error && (
          <p role="alert" className="text-sm text-red-700 dark:text-red-400">
            {error}
          </p>
        )}
        <p className="text-xs text-black/55 dark:text-white/55">
          Viewers read; analysts also act on alerts and decisions; admins also manage sources and people.
        </p>
      </CardContent>
    </Card>
  );
}
