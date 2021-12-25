using System;
using System.IO;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;
using System.Linq;
using System.Diagnostics;
using System.Collections.Generic;
using Microsoft.Diagnostics.NETCore.Client;
using System.Diagnostics.Tracing;

namespace sampler
{
    class CallStackNode : Dictionary<string, CallStackNode>
    {
        public CallStackNode(int callsCount) : base(StringComparer.OrdinalIgnoreCase)
        {
            CallsCount = callsCount;
        }

        public int CallsCount { get; set; }
    }

    class Program
    {
        private static TextWriter log = Environment.GetEnvironmentVariable("ENABLE_TRACEEVENT_LOG") == null ? TextWriter.Null : Console.Out;

        static void Main(string[] args)
        {
            if (args.Length == 2 && args[0] == "trace" && int.TryParse(args[1], out var pid))
            {
                StartTrace(pid);
            }
            else if (args.Length >= 1 && args[0] == "analyze")
            {
                Analyze(args.Length > 1 ? int.Parse(args[1]) : 0);
            }
            else
            {
                Console.WriteLine("Usage: sampler trace {pid} | analyze [max-depth]");
            }
        }

        private static void StartTrace(int pid)
        {
            var client = new DiagnosticsClient(pid);

            var providers = new[] {
                new EventPipeProvider("Microsoft-DotNETCore-SampleProfiler", EventLevel.Informational, 0xF00000000000),
                new EventPipeProvider("Microsoft-Windows-DotNETRuntime", EventLevel.Informational, 0x14C14FCCBD)
            };

            using var session = client.StartEventPipeSession(providers, true);

            Console.CancelKeyPress += (o, ev) => { ev.Cancel = true; session.Stop(); };

            using var fs = File.OpenWrite("trace.nettrace");
            session.EventStream.CopyTo(fs);
        }

        private static CallStackNode AddOrUpdateChildNode(CallStackNode node, TraceCallStack callStack)
        {
            var decodeAddress = $"{callStack.CodeAddress.ModuleName}!{callStack.CodeAddress.FullMethodName}";
            if (node.TryGetValue(decodeAddress, out var childNode))
            {
                childNode.CallsCount += 1;
            }
            else
            {
                childNode = new CallStackNode(1);
                node.Add(decodeAddress, childNode);
            }
            return childNode;
        }

        private static CallStackNode ProcessStackFrame(CallStackNode node, TraceCallStack callStack)
        {
            var caller = callStack.Caller;
            if (caller == null)
            {
                // root node
                node.CallsCount = node.CallsCount + 1;
            }
            var childNode = caller == null ? AddOrUpdateChildNode(node, callStack) : ProcessStackFrame(node, caller);
            return AddOrUpdateChildNode(childNode, callStack);
        }

        private static CallStackNode BuildCallStackTree(TraceLog traceLog, int pid, int tid)
        {
            var callStacks = new CallStackNode(0);
            foreach (var ev in traceLog.Events.Where(ev => ev.ProcessID == pid && ev.ThreadID == tid
                            && ev.ProviderName == "Microsoft-DotNETCore-SampleProfiler"
                            && ev.Task == TraceEventTask.Default && (int)ev.Opcode == 1))
            {
                ProcessStackFrame(callStacks, ev.CallStack());
            }

            return callStacks;
        }

        private static void PrintCallStacks(string threadDesc, int maxDepth, CallStackNode node)
        {
            void PrintCallStacksRecursive(string name, int depth, CallStackNode node)
            {
                var indentation = String.Concat(Enumerable.Repeat("| ", depth));
                Console.WriteLine($"{indentation}├─ {name} [{node.CallsCount}]");
                if (node.Count == 0 || (maxDepth > 0 && depth >= maxDepth))
                {
                    return;
                }
                foreach (var kv in node)
                {
                    PrintCallStacksRecursive(kv.Key, depth + 1, kv.Value);
                }
            }
            PrintCallStacksRecursive(threadDesc, 0, node);
        }

        private static void Analyze(int maxDepth)
        {
            var options = new TraceLogOptions() {
                ConversionLog = log
            };
            var etlxFilePath = TraceLog.CreateFromEventPipeDataFile("trace.nettrace", options: options);
            var traceLog = TraceLog.OpenOrConvert(etlxFilePath, options);

            var sw = Stopwatch.StartNew();

            var proc = traceLog.Processes.Single();

            foreach (var thr in proc.Threads)
            {
                var pid = thr.Process.ProcessID;
                var callStacks = BuildCallStackTree(traceLog, pid, thr.ThreadID);

                PrintCallStacks($"Thread ({thr.ThreadID}) '{thr.ThreadInfo}'", maxDepth, callStacks);
            }
            Console.WriteLine($"[{sw.ElapsedMilliseconds} ms] Completed call stack analysis");
        }
    }
}
