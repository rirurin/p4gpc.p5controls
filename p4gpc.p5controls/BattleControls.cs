using p4gpc.p5controls.Configuration;
using Reloaded.Hooks.Definitions;
using Reloaded.Hooks.Definitions.Enums;
using Reloaded.Hooks.Definitions.X86;
using Reloaded.Memory.Sigscan;
using Reloaded.Memory.Sources;
using Reloaded.Mod.Interfaces;
using System;
using System.Runtime.InteropServices;
using static Reloaded.Hooks.Definitions.X86.FunctionAttribute;
using static p4gpc.p5controls.Utils;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace p4gpc.p5controls
{
    class BattleControls
    {
        public Config Configuration { get; set; }
        private Utils _utils;

        // Classes
        private IReloadedHooks _hooks;
        private int _baseAddress;
        private IMemory _memory;

        // Reverse Wrappers
        private IReverseWrapper<SelectedOptionFunction> _selectedReverseWrapper;
        private IReverseWrapper<SelectedEnemyFunction> _selectedEnemyReverseWrapper;
        private IReverseWrapper<AttackAnalysisFunction> _attackAnalysisReverseWrapper;
        private IReverseWrapper<BtlActionFunction> _btlActionReverseWrapper;
        private IReverseWrapper<PersonaMenuFunction> _personaMenuReverseWrapper;
        private IReverseWrapper<TacticsMenuFunction> _tacticsMenuReverseWrapper;

        // ASM Hooks
        private IAsmHook _selectedMenuHook;
        private IAsmHook _blockInput;
        private IAsmHook _selectedEnemyHook;
        private IAsmHook _btlAction;
        private IAsmHook _personaMenu;
        private IAsmHook _tacticsMenu;

        // Variables
        public int esiValue;
        public int inBattle;
        public bool inMainBattleMenu = true;
        public int hInput = 0;
        public bool NextTurn = false;
        public int menuSelection = 0;
        public bool exitingFromList = false;
        public bool inPersonaMenu = false;
        public int personaMenuTargetEax = 0;
        public int menuLayer = 0;
        public bool risenEdge = false;
        public int tacticsMenuActive = 0;
        private int personaMenuStatus = 0;

        // Global pointers
        public long menuSelectPointer = 0;
        public long exitAttackPointer = 0;
        public long nextTurnPointer = 0;

        public BattleControls(Utils utils, int baseAddress, Config config, IMemory memory, IReloadedHooks hooks)
        {
            Configuration = config;
            _utils = utils;
            _memory = memory;
            _baseAddress = baseAddress;
            _hooks = hooks;
            try
            {
                string[] selectedItemFunction =
                {
                    $"use32",
                    $"{hooks.Utilities.PushCdeclCallerSavedRegisters()}",
                    $"{hooks.Utilities.GetAbsoluteCallMnemonics(menuItemSelected, out _selectedReverseWrapper)}",
                    $"{hooks.Utilities.PopCdeclCallerSavedRegisters()}",
                };

                string[] blockInputFunction =
                {
                    $"use32",
                    $"mov edi, 16384",
                };
                string[] selectedEnemyFunction =
                {
                    $"use32",
                    $"{hooks.Utilities.PushCdeclCallerSavedRegisters()}",
                    $"{hooks.Utilities.GetAbsoluteCallMnemonics(menuEnemySelected, out _selectedEnemyReverseWrapper)}",
                    $"{hooks.Utilities.PopCdeclCallerSavedRegisters()}",
                };
                string[] attackAnalysisFunction =
                {
                    $"use32",
                    $"{hooks.Utilities.PushCdeclCallerSavedRegisters()}",
                    $"{hooks.Utilities.GetAbsoluteCallMnemonics(attackAnalysis, out _attackAnalysisReverseWrapper)}",
                    $"{hooks.Utilities.PopCdeclCallerSavedRegisters()}",
                };
                string[] btlActionFunction =
                {
                    $"use32",
                    $"{hooks.Utilities.PushCdeclCallerSavedRegisters()}",
                    $"{hooks.Utilities.GetAbsoluteCallMnemonics(btlAction, out _btlActionReverseWrapper)}",
                    $"{hooks.Utilities.PopCdeclCallerSavedRegisters()}",
                };
                string[] personaMenuFunction =
                {
                    $"use32",
                    $"mov eax, 3",
                    $"{hooks.Utilities.PushCdeclCallerSavedRegisters()}",
                    $"{hooks.Utilities.GetAbsoluteCallMnemonics(runPersonaMenu, out _personaMenuReverseWrapper)}",
                    $"{hooks.Utilities.PopCdeclCallerSavedRegisters()}",
                };
                string[] tacticsFunction =
                {
                    $"use32",
                    $"{hooks.Utilities.PushCdeclCallerSavedRegisters()}",
                    $"{hooks.Utilities.GetAbsoluteCallMnemonics(activePartyMember, out _tacticsMenuReverseWrapper)}",
                    $"{hooks.Utilities.PopCdeclCallerSavedRegisters()}",
                };

                // scanner init code
                using var thisProcess = Process.GetCurrentProcess();
                _baseAddress = thisProcess.MainModule.BaseAddress.ToInt32();
                using var scanner = new Scanner(thisProcess, thisProcess.MainModule);

                // tick function

                var _tick = new Thread(tick);
                _tick.Start();

                void tick()
                {
                    var stopwatch = Stopwatch.StartNew();
                    while (true)
                    {
                        _memory.SafeRead((IntPtr)(_baseAddress + 0x21A967B0), out inBattle); // is the user in battle?
                        Thread.Sleep(50);
                    }
                }

                // sig scan for all the addresses :raidoufrost:

                // hooks (grab register information from here)
                long menuHookPointer = 0;
                long inputBlockPointer = 0;
                long selectedEnemyPointer = 0;
                long battleActionPointer = 0;
                long rushModePointer = 0;
                long personaMenuPointer = 0;
                long assistButtonPointer = 0;
                long personaSwitcherPointer = 0;
                long tacticsPointer = 0;
                
                // Sig Scan for addresses asynchronously so it doesn't take like 5 hours
                
                List<Task> pointers = new List<Task>();
                pointers.Add(Task.Run(() =>
                {
                    menuHookPointer = SigScan("53 56 57 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 7D 0C F3 0F 10 05", "Menu Hook Pointer");
                }));
                pointers.Add(Task.Run(() =>
                {
                    inputBlockPointer = SigScan("89 3D ?? ?? ?? ?? 89 C1 A3 ?? ?? ?? ?? 80 FA D0 76 ??", "Input Block Pointer");
                })); // blocks user input temporarily to stop weird stuff happening
                pointers.Add(Task.Run(() =>
                {
                    selectedEnemyPointer = SigScan("8B ?? ?? ?? 66 ?? ?? ?? 74 ?? 80 ?? ?? ?? 66", "Selected Enemy Pointer");
                })); // reads a value corresponding to the highlighted enemy when in Attack mode
                pointers.Add(Task.Run(() =>
                {
                    battleActionPointer = SigScan("66 89 77 0C C7 47 24 00 00 00 00 57 8D 04 40 8B 04 85", "Battle Action Pointer");
                }));
                pointers.Add(Task.Run(() =>
                {
                    rushModePointer = SigScan("F7 05 ?? ?? ?? ?? 00 50 00 00 0F 84 ?? ?? ?? ?? E8", "Rush Mode Pointer");
                })); // the point in memory which handles which key is used to activate Rush mode
                pointers.Add(Task.Run(() =>
                {
                    personaMenuPointer = SigScan("0F B7 D8 89 D8 83 E8 01 0F 84", "Persona Menu Pointer");
                }));
                pointers.Add(Task.Run(() =>
                {
                    assistButtonPointer = SigScan("A9 ?? ?? ?? ?? 74 ?? 66 ?? ?? ?? EB ?? F3", "Assist Button Pointer");
                })); // point in memory that changes key for All Out Attack/Party Assist
                pointers.Add(Task.Run(() =>
                {
                    menuSelectPointer = SigScan("85 37 FF FF FF 0F", "Menu Select Pointer");
                })); // forces highlighted menu option to get selected
                pointers.Add(Task.Run(() =>
                {
                    exitAttackPointer = SigScan("74 ?? BA 12 27 00 00 B9 04 00 00 00 E8 ?? ?? ?? ?? 8B 4E 18", "Exit Attack Pointer");
                })); // exits the attack menu
                pointers.Add(Task.Run(() =>
                {
                    nextTurnPointer = SigScan("0F 84 ?? ?? ?? ?? 66 85 F6 0F 85 ?? ?? ?? ?? 8B ?? ?? A9", "Next Turn Pointer");
                })); // writes memory to handle the next turn functionality
                pointers.Add(Task.Run(() =>
                {
                    tacticsPointer = SigScan("66 ?? ?? ?? ?? ?? ?? ?? 75 ?? 31 ?? 8D", "Tactics Highlighted Pointer");
                })); // used to detect if the user can access tactics or persona menu depending on the active party member
                /*
                pointers.Add(Task.Run(() =>
                {
                    personaSwitcherPointer = SigScan("F7 46 ?? ?? ?? ?? ?? 74 AF", "Persona Switcher Pointer");
                })); // pointer that determines if the persona menu can be accessed
                */
                try
                {
                    Task.WaitAll(pointers.ToArray());
                } catch (Exception e)
                {
                    throw e;
                }

                battleActionPointer = battleActionPointer + 0xF;

                _utils.Log("Hooking into battle functions");

                _selectedMenuHook =     hooks.CreateAsmHook(selectedItemFunction, (menuHookPointer), AsmHookBehaviour.ExecuteFirst).Activate();
                _blockInput =           hooks.CreateAsmHook(blockInputFunction, (inputBlockPointer), AsmHookBehaviour.ExecuteFirst).Activate();
                _selectedEnemyHook =    hooks.CreateAsmHook(selectedEnemyFunction, (selectedEnemyPointer), AsmHookBehaviour.ExecuteFirst).Activate();
                _btlAction =            hooks.CreateAsmHook(btlActionFunction, (battleActionPointer), AsmHookBehaviour.ExecuteFirst).Activate();
                _personaMenu =          hooks.CreateAsmHook(personaMenuFunction, (personaMenuPointer), AsmHookBehaviour.ExecuteFirst).Activate();
                _tacticsMenu =          hooks.CreateAsmHook(tacticsFunction, (tacticsPointer), AsmHookBehaviour.ExecuteFirst).Activate();

                _blockInput.Disable();
                _personaMenu.Disable();

                // set the "Rush Mode" keybind from Triangle to Start

                _memory.SafeWrite((IntPtr)(rushModePointer), 0x0000400821E881C405F7);
                _memory.SafeWrite((IntPtr)(rushModePointer + 0x1C), 0x0000000821E881C405F7);

                // Replace Cross in All Out Attack/Party Assist with Triangle
                _memory.SafeWrite((IntPtr)(assistButtonPointer - 0x5B), 0x00001000);

                // Remove holding RB for next turn
                _memory.SafeWrite((IntPtr)(nextTurnPointer - 0x1F), 0x00000000);

            } catch (Exception e)
            {
                _utils.LogError($"Error hooking battle functions, Unloading mod", e);
            }
        }
        // Sigscan Function

        public long SigScan(string pattern, string functionName)
        {
            try
            {
                using var thisProcess = Process.GetCurrentProcess();
                using var scanner = new Scanner(thisProcess, thisProcess.MainModule);
                long functionAddress = scanner.CompiledFindPattern(pattern).Offset + _baseAddress;
                 _utils.LogSuccess($"Found function {functionName} at 0x{functionAddress:X}");
                return functionAddress;
            } catch (Exception e)
            {
                _utils.LogError($"Error occured while finding the function {functionName}, function terminated. Please report this, including a list of your other Reloaded-II mods and your version of P4G to *insert gamebanana link here*", e);
                return -1;
            }
        }
        
        // Menu Functions

        // Assisting Functions

        public void forceEnterMenu()
        {
            _memory.SafeWrite((IntPtr)(exitAttackPointer), 0x12BA2274);
            _memory.SafeWrite((IntPtr)esiValue, menuSelection);
            _memory.SafeWrite((IntPtr)(menuSelectPointer), 0xFFFF3784);
        }

        // Main Menu Functions
        public void afterInput()
        {
            _utils.LogDebug($"Battle Menu Input Detected...");
            for (int k = 0; k < 4; k++)
            {
                if ((menuSelection == 5 || menuSelection == 3) && personaMenuStatus == 1)
                {
                    _personaMenu.Disable();
                }
                Thread.Sleep(10);
            }
            /*
            _utils.LogDebug($"{personaMenuStatus}");
            if (menuSelection == 5 || menuSelection == 3)
            {
                _personaMenu.Disable();
            }
            */
            while (risenEdge && menuSelection != 2)
            {
                Thread.Sleep(10);
            }
            _memory.SafeWrite((IntPtr)(menuSelectPointer), 0xFFFF3785);
            _utils.LogDebug($"Now safe to exit out, disabling input blocker");
            _blockInput.Disable();
        }
        public void afterInputNextTurn()
        {
            _utils.LogDebug($"Battle Menu Input Detected...");
            Thread.Sleep(150);
            _utils.LogDebug($"Now safe to exit out, disabling input blocker");
            // hInput = 0x0;
            _blockInput.Disable();
        }
        public void beginTurn()
        {
            _blockInput.Enable();
            Thread.Sleep(100);
            _memory.SafeWrite((IntPtr)esiValue, menuSelection);
            _memory.SafeWrite((IntPtr)(menuSelectPointer), 0xFFFF3784);
            if (menuSelection == 3) inMainBattleMenu = true;
            _blockInput.Disable();
        }
        public void Input()
        {
            var _afterInput = new Thread(afterInput);
            _memory.SafeWrite((IntPtr)(exitAttackPointer), 0x12BA2275);
            _memory.SafeWrite((IntPtr)(menuSelectPointer), 0xFFFF3785);
            _blockInput.Enable();
            Thread.Sleep(40);
            forceEnterMenu();
            //inMainBattleMenu = false;
            if (menuSelection != 5)
            {
                inMainBattleMenu = !inMainBattleMenu;
            }
            _afterInput.Start();
        }
        public void InputFromList()
        {
            exitingFromList = true;
            var _afterInput = new Thread(afterInput);
            _blockInput.Enable();
            Thread.Sleep(75);
            exitingFromList = false;
            forceEnterMenu();
            //inMainBattleMenu = false;
            if (menuSelection != 5)
            {
                inMainBattleMenu = !inMainBattleMenu;
            }
            _afterInput.Start();
        }
        public void ExitInnerMenu()
        {
            Thread.Sleep(50);
            _utils.LogDebug($"menulayer do be {menuLayer}");
            menuLayer -= 1;
        }
        public void ExitPersonaMenu()
        {
            while (risenEdge)
            {
                Thread.Sleep(10);
            }
            _blockInput.Enable();
            Thread.Sleep(40);
            _blockInput.Disable();
            menuSelection = 4;
            forceEnterMenu();
        }

        // Input handler
        public void SendInput(int input, bool risingEdge)
        {
            _utils.LogDebug($"Input was {(Input)input} and was {(risingEdge ? "rising" : "falling")} edge");
            if (inBattle != 0)
            {
                // P5 MENU REFERENCE:

                // triangle - Persona
                // square - Item
                // Circle - Guard
                // Cross - Attack (one enemy, goes instantly to attack (I don't remember if P4G does this so keep note of that))
                // Start - Rush
                // LB - Analyse (actually is in P4G, no need to change)
                // L2 - Tactics (substitude for Left since the Vita has no L2)
                // Down - Next Turn (RB in P4G)
                // RB - Assist (that's just analyse?)

                // All Out Attack is Triangle

                if (risingEdge)
                {
                    risenEdge = true;
                }
                else
                {
                    risenEdge = false;
                }

                if (inMainBattleMenu)
                {
                    if (input == 0x1000) // TRIANGLE - SKILL/PERSONA
                    {
                        menuSelection = 4;
                        var _input = new Thread(Input);
                        _input.Start();

                    }
                    if (input == 0x8000) // SQUARE - ITEM
                    {
                        menuSelection = 6;
                        var _input = new Thread(Input);
                        _input.Start();
                    }
                    if (input == 0x2000) // CIRCLE - GUARD
                    {
                        if (NextTurn) // Cancel Next Turn
                        {
                            // _memory.SafeWrite((IntPtr)(_baseAddress + 0x21FE8220), 0x000000C6840F);
                            _memory.SafeWrite((IntPtr)(_baseAddress + 0x21FE9492), 0x009C840F);
                            NextTurn = !NextTurn;
                        }
                        else
                        {
                            menuSelection = 2;
                            var _input = new Thread(Input);
                            _input.Start();
                        }
                    }
                    if (input == 0x4000) // CROSS - ATTACK
                    {

                    }
                    if (input == 0x8) // START - RUSH
                    {
                    }
                    if (input == 0x1) // SELECT - ESCAPE
                    {
                        menuSelection = 7;
                        var _input = new Thread(Input);
                        _input.Start();
                    }
                    if (input == 0x400) // LB - ANALYZE (for real)
                    {
                        // _memory.SafeWrite((IntPtr)(menuSelect), 0x70732E33);
                    }
                    if (input == 0x20) // LEFT - CHANGE TARGET
                    {

                    }
                    if (input == 0x80) // RIGHT - CHANGE TARGET
                    {

                    }
                    if (input == 0x800) // RB - ASSIST
                    {
                    }
                    if (input == 0x10 && tacticsMenuActive == 1) // UP - TACTICS
                    {
                        // substitute for L2 not being in Vita controller set
                        menuSelection = 1;
                        var _input = new Thread(Input);
                        _input.Start();
                    }
                }
                else
                {
                    if (input == 0x2000 && menuLayer == 0) // CIRCLE - GO BACK
                    {
                        if (menuSelection == 5)
                        {
                            // _personaMenu.Enable();
                            personaMenuStatus = 0;
                        }
                        // inMainBattleMenu = true;
                        menuSelection = 3;
                        var _input = new Thread(Input);
                        _input.Start();
                    }
                    if (menuSelection == 1)
                    {
                        if (input == 0x2000)
                        {
                            var _menu = new Thread(ExitInnerMenu);
                            _menu.Start();
                        }
                        if (input == 0x4000 && risingEdge)
                        {
                            if (menuLayer == 0)
                            {
                                menuLayer = 1;
                                _utils.Log("menulayer do be 1");
                            }
                            else
                            {
                                menuLayer = 0;
                                _utils.Log("menulayer do be 0");
                            }
                        }
                    }
                    if (menuSelection == 4)
                    {
                        if ((input == 0x400 || input == 0x800) && risingEdge && tacticsMenuActive == 1) // SWITCH PERSONAS
                        {
                            menuSelection = 5;
                            menuLayer = 1;
                            personaMenuStatus = 0;
                            _personaMenu.Enable();
                            var _input = new Thread(Input);
                            _input.Start();
                        }
                        if (input == 0x2000 && risingEdge)
                        {
                            var _menu = new Thread(ExitInnerMenu);
                            _menu.Start();
                        }
                        if (input == 0x4000 && risingEdge)
                        {
                            menuLayer += 1;
                            _utils.LogDebug($"menulayer do be {menuLayer}");
                        }
                        if (input == 0x8000 && risingEdge)
                        {
                            if (menuLayer == 0)
                            {
                                menuLayer = 1;
                                _utils.LogDebug($"menulayer do be {menuLayer}");
                            }
                            else
                            {
                                menuLayer -= 1;
                                _utils.LogDebug($"menulayer do be {menuLayer}");
                            }
                        }
                    }
                    if (menuSelection == 5)
                    {
                        if (input == 0x2000)
                        {
                            if (menuLayer == 2)
                            {
                                menuLayer = 1;
                            }
                            else
                            {
                                menuLayer = 0;
                                var _input = new Thread(ExitPersonaMenu);
                                _input.Start();
                            }
                        }
                        if (input == 0x8000 && risingEdge)
                        {
                            menuLayer = 2;
                        }
                    }
                    if (menuSelection == 6)
                    {
                        if (input == 0x2000)
                        {
                            var _menu = new Thread(ExitInnerMenu);
                            _menu.Start();
                        }
                        if (input == 0x8000 && risingEdge)
                        {
                            if (menuLayer == 0)
                            {
                                menuLayer = 1;
                                _utils.LogDebug($"menulayer do be {menuLayer}");
                            }
                            else
                            {
                                menuLayer -= 1;
                                _utils.LogDebug($"menulayer do be {menuLayer}");
                            }
                        }
                        if (input == 0x4000 && risingEdge)
                        {
                            menuLayer += 1;
                            _utils.LogDebug($"menulayer do be {menuLayer}");
                        }
                    }
                }
                if (input == 0x40 && menuSelection == 3) // DOWN - NEXT TURN
                {
                    if (NextTurn)
                    {
                        // _memory.SafeWrite((IntPtr)(_baseAddress + 0x21FE8220), 0x000000C6840F); NEXT TURN, MAIN BATTLE MENU
                        _memory.SafeWrite((IntPtr)(nextTurnPointer), 0x009C840F);
                    }
                    else
                    {
                        // _memory.SafeWrite((IntPtr)(_baseAddress + 0x21FE8220), 0x000000C6800F); NEXT TURN, MAIN BATTLE MENU
                        _memory.SafeWrite((IntPtr)(nextTurnPointer), 0x009C850F);
                    }
                    NextTurn = !NextTurn;
                    // _memory.SafeWrite((IntPtr)(_baseAddress + 0x21FE8220), 0x000000C6840F);
                }
            }
        }

        // Functions reading from registers
        public void menuItemSelected(int edi)
        {
            esiValue = edi + 4;
            _memory.SafeRead((IntPtr)esiValue, out byte highlightedMenuOption); // what is the highlighted menu item?
        }
        public void menuEnemySelected(int esi)
        {
            _utils.LogDebug($"Enemy Selected ESI: {esi}");
        }
        public void attackAnalysis(int esi)
        {
            int esiOffset = esi + 2;
            _memory.SafeRead((IntPtr)esiOffset, out byte highlightedMenuOption);
        }
        public void btlAction(int eax)
        {
            _utils.LogDebug($"Battle Action EAX: {eax}");
            // eax 6 or eax 51
            if (eax == 15 || eax == 90)
            {
                if (eax == 15) menuSelection = 3;
                if (eax == 90) menuSelection = 4;
                menuLayer = 0;
                _utils.LogDebug($"Begin turn");
                var _beginTurn = new Thread(beginTurn);
                _beginTurn.Start();
            }
        }
        public void runPersonaMenu(int eax)
        {
            _utils.LogDebug($"Persona Menu EAX: {eax}, {personaMenuStatus}");
            if (eax == 3)
            {
                personaMenuStatus = 1;
            }
        }
        public void activePartyMember (int eax)
        {
            // _utils.LogDebug($"{eax}");
            _memory.SafeRead((IntPtr)(eax + 0xA4), out int activeMember);
            if (activeMember == 1)
            {
                tacticsMenuActive = 1; // yu
            } else
            {
                tacticsMenuActive = 0; // not yu
            }
        }
        // Hooked function delegate
        [Function(Register.edi, Register.edi, StackCleanup.Callee)]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void SelectedOptionFunction(int edi);

        [Function(Register.esi, Register.esi, StackCleanup.Callee)]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void SelectedEnemyFunction(int esi);

        [Function(Register.esi, Register.esi, StackCleanup.Callee)]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void AttackAnalysisFunction(int esi);

        [Function(Register.eax, Register.eax, StackCleanup.Callee)]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void BtlActionFunction(int eax);

        [Function(Register.eax, Register.eax, StackCleanup.Callee)]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void PersonaMenuFunction(int eax);

        [Function(Register.eax, Register.eax, StackCleanup.Callee)]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void TacticsMenuFunction(int eax);

    }
}
