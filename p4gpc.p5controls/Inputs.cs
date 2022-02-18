using p4gpc.p5controls.Configuration;
using Reloaded.Hooks.Definitions;
using Reloaded.Hooks.Definitions.X86;
using Reloaded.Hooks.Definitions.Enums;
using Reloaded.Mod.Interfaces;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using static Reloaded.Hooks.Definitions.X86.FunctionAttribute;
using Reloaded.Memory.Sources;
using static p4gpc.p5controls.Utils;
using Reloaded.Memory.Sigscan;
using Reloaded.Memory.Sigscan.Structs;
using System.Threading;
using System.Threading.Tasks;

namespace p4gpc.p5controls
{
    class Inputs
    {
        private IReloadedHooks _hooks;
        // Keeps track of the last inputs for rising/falling edge detection
        private int[] controllerInputHistory = new int[10];
        private int lastControllerInput = 0;
        private int lastKeyboardInput = 0;
        // For accessing memory
        private IMemory _memory;
        // Base address (probably won't ever change)
        private int _baseAddress;

        // Modules
        private BattleControls _battle;
        private Config _config { get; set; }
        private Utils _utils;

        private bool _switcher;

        public int inBattle;
        public bool otherPartyMembers = true;

        // Pointers

        public Inputs(IReloadedHooks hooks, Config configuration, Utils utils, bool switcher)
        {
            // Initialise private variables
            _config = configuration;
            _hooks = hooks;
            _memory = new Memory();
            _utils = utils;
            _switcher = switcher;

            _utils.Log("Input.cs");

            // Create input hook
            _utils.LogIntro();
            _utils.Log("Hooking into input functions");

            try
            {
                using var thisProcess = Process.GetCurrentProcess();
                _baseAddress = thisProcess.MainModule.BaseAddress.ToInt32();

                // Create function hooks
                using var scanner = new Scanner(thisProcess, thisProcess.MainModule);

                long switcherAddress = 0;
                long instantSwitch1 = 0;
                long instantSwitch2 = 0;

                if (!_switcher) _utils.Log("Could not find Infinite Persona Switcher, applying patches to replicate switcher");
                // Check to see if another mod has taken that particular memory address
                // If TinyAdditions has taken the input hook first,
                    // Get address of input hook and write that to input

                List<Task> pointers = new List<Task>();
                if (!_switcher)
                {
                    pointers.Add(Task.Run(() =>
                    {
                        // controllerPointer = scanner.CompiledFindPattern("0F AB D3 89 5D C8").Offset + _baseAddress;
                        switcherAddress = SigScan("F7 46 ?? ?? ?? ?? ?? 74 AF", "Persona Switcher Pointer");
                    }));
                    pointers.Add(Task.Run(() =>
                    {
                        // controllerPointer = scanner.CompiledFindPattern("0F AB D3 89 5D C8").Offset + _baseAddress;
                        instantSwitch1 = SigScan("0F B7 7B 78 BA 0C 00 00 00 8B 73 38", "Persona Switcher Animation Cancel 1");
                    }));
                    pointers.Add(Task.Run(() =>
                    {
                        // controllerPointer = scanner.CompiledFindPattern("0F AB D3 89 5D C8").Offset + _baseAddress;
                        instantSwitch2 = SigScan("A1 ?? ?? ?? ?? 8B 53 38 6A 00 6A 00", "Persona Switcher Animation Cancel 2");
                    }));
                }

                try
                {
                    Task.WaitAll(pointers.ToArray());
                }
                catch (Exception e)
                {
                    throw e;
                }

                if (!_switcher)
                {
                    _memory.SafeWrite((IntPtr)switcherAddress + 0x7, 0xAF70);
                    _memory.SafeWrite((IntPtr)instantSwitch1, 0x900000011FE9);
                    _memory.SafeWrite((IntPtr)instantSwitch2, 0x000000AAE9);
                }

                _utils.Log("Successfully hooked into input functions");
                _battle = new BattleControls(_utils, _baseAddress, _config, _memory, _hooks);
            }
            catch (Exception e)
            {
                _utils.LogError($"Error hooking into input functions. Unloading mod", e);
                Suspend();
                return;
            }
            // Load tick function
            var _tick = new Thread(tick);
            _tick.Start();

            void tick()
            {
                var stopwatch = Stopwatch.StartNew();
                while (true)
                {
                    _memory.SafeRead((IntPtr)(_baseAddress + 0x21A967B0), out inBattle); // is the user in battle?
                    Thread.Sleep(50);
                    _memory.SafeRead((IntPtr)(_baseAddress + 0x49DC3C4), out int partyMembers);
                    otherPartyMembers = partyMembers == 0 ? false : true;
                }
            }
        }

        public long SigScan(string pattern, string functionName)
        {
            try
            {
                using var thisProcess = Process.GetCurrentProcess();
                using var scanner = new Scanner(thisProcess, thisProcess.MainModule);
                long functionAddress = scanner.CompiledFindPattern(pattern).Offset + _baseAddress;
                _utils.LogSuccess($"Found function {functionName} at 0x{functionAddress:X}");
                return functionAddress;
            }
            catch (Exception e)
            {
                _utils.LogError($"Error occured while finding the function {functionName}, function terminated. Please report this, including a list of your other Reloaded-II mods and your version of P4G to *insert gamebanana link here*", e);
                return -1;
            }
        }

        public void Suspend()
        {
        }
        public void Resume()
        {
        }

        public void UpdateConfiguration(Config configuration)
        {
            _config = configuration;
        }

        // Function that reads all inputs
        public void InputHappened(int input, bool risingEdge, bool keyboard)
        {
            _utils.LogDebug($"Input was {(Input)input} and was {(risingEdge ? "rising" : "falling")} edge");
            _battle.SendInput(input, risingEdge, true);

        }
    }
}
