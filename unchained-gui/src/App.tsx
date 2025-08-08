import { useEffect, useRef, useState } from "react";
import "./index.css";
import { invoke } from "@tauri-apps/api/core";

function Button(
  props: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "default" | "secondary" | "destructive" }
) {
  const { className = "", variant = "default", ...rest } = props;
  const color =
    variant === "secondary"
      ? "bg-secondary text-secondary-foreground hover:opacity-90"
      : variant === "destructive"
      ? "bg-destructive text-destructive-foreground hover:opacity-90"
      : "bg-primary text-primary-foreground hover:opacity-90";
  return (
    <button
      className={`inline-flex items-center justify-center rounded-md px-4 py-2 text-sm font-medium shadow ${color} ${className}`}
      {...rest}
    />
  );
}

export default function App() {
  const [running, setRunning] = useState(false);
  const [mining, setMining] = useState(false);
  const [logs, setLogs] = useState<string>("");
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const unsubs: Array<() => void> = [];
    import("@tauri-apps/api/event").then(({ listen }) => {
      Promise.all([
        listen<string>("node:stdout", (e) => setLogs((l) => l + e.payload)),
        listen<string>("node:stderr", (e) => setLogs((l) => l + e.payload)),
        listen<number>("node:exit", () => setRunning(false)),
      ]).then((offs) => unsubs.push(...offs.map((o) => () => o())));
    });
    return () => unsubs.forEach((u) => u());
  }, []);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [logs]);

  async function startNode(miningMode: boolean) {
    const args = miningMode ? ["--quiet-net", "mine"] : ["--quiet-net"];
    try {
      await invoke("start_node", { args });
      setRunning(true);
      setMining(miningMode);
    } catch (e) {
      setLogs((l) => l + "\nError starting node: " + String(e) + "\n");
    }
  }
  async function stopNode() {
    try {
      await invoke("stop_node");
    } catch (e) {
      setLogs((l) => l + "\nError stopping node: " + String(e) + "\n");
    } finally {
      setRunning(false);
      setMining(false);
    }
  }

  return (
    <div className="container mx-auto p-6">
      <h1 className="text-2xl font-semibold mb-4">Unchained Node</h1>
      <div className="flex gap-2 mb-4">
        <Button onClick={() => startNode(false)} disabled={running}>
          Start Node
        </Button>
        <Button onClick={() => startNode(true)} disabled={running}>
          Start Mining
        </Button>
        <Button onClick={stopNode} disabled={!running} variant="destructive">
          Stop
        </Button>
      </div>
      <div className="text-sm text-muted-foreground mb-2">
        Status: {running ? (mining ? "Mining" : "Running") : "Stopped"}
      </div>
      <div
        ref={logRef}
        className="bg-card text-card-foreground rounded-md border border-border h-[360px] overflow-auto p-3 whitespace-pre-wrap font-mono text-xs"
      >
        {logs || "Logs will appear here..."}
      </div>
    </div>
  );
}
