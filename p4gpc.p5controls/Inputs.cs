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
        // For calling C# code from ASM.
        private IReverseWrapper<KeyboardInputFunction> _keyboardReverseWrapper;
        private IReverseWrapper<ControllerInputFunction> _controllerReverseWrapper;
        // For maniplulating input reading hooks
        private IAsmHook _keyboardHook;
        private IAsmHook _controllerHook;
        // Keeps track of the last inputs for rising/falling edge detection
        private int[] controllerInputHistory = new int[10];
        private int lastControllerInput = 0;
        private int lastKeyboardInput = 0;
        // For accessing memory
        private IMemory _memory;
        // Base address (probably won't ever change)
        private int _baseAddress;
        // Functionalities
        private BattleControls _battle;

        // Current mod configuration
        private Config _config { get; set; }
        private Utils _utils;

        // Pointers

        public Inputs(IReloadedHooks hooks, Config configuration, Utils utils)
        {
            // Initialise private variables
            _config = configuration;
            _hooks = hooks;
            _memory = new Memory();
            _utils = utils;

            // Create input hook
            _utils.LogIntro();
            _utils.Log("Hooking into input functions");

            try
            {
                using var thisProcess = Process.GetCurrentProcess();
                _baseAddress = thisProcess.MainModule.BaseAddress.ToInt32();

                // Define functions (they're the same but use different reverse wrappers)
                string[] keyboardFunction =
                {
                    $"use32",
                    $"{hooks.Utilities.GetAbsoluteCallMnemonics(KeyboardInputHappened, out _keyboardReverseWrapper)}",
                };
                string[] controllerFunction =
                {
                    $"use32",
                    $"{hooks.Utilities.GetAbsoluteCallMnemonics(ControllerInputHappened, out _controllerReverseWrapper)}",
                };

                // Create function hooks
                using var scanner = new Scanner(thisProcess, thisProcess.MainModule);

                int keyboardPointer = 0;
                int controllerPointer = 0;

                List<Task> pointers = new List<Task>();
                pointers.Add(Task.Run(() =>
                {
                    keyboardPointer = scanner.CompiledFindPattern("85 DB 74 05 E8 ?? ?? ?? ?? 8B 7D F8").Offset + _baseAddress;
                })); // Read input from keyboard
                pointers.Add(Task.Run(() =>
                {
                    controllerPointer = scanner.CompiledFindPattern("0F AB D3 89 5D C8").Offset + _baseAddress;
                })); // Read input from controller

                try
                {
                    Task.WaitAll(pointers.ToArray());
                }
                catch (Exception e)
                {
                    throw e;
                }

                _keyboardHook = hooks.CreateAsmHook(keyboardFunction, keyboardPointer, AsmHookBehaviour.ExecuteFirst).Activate(); // call 85 DB 74 05 E8 7F 81 13 DA
                _controllerHook = hooks.CreateAsmHook(controllerFunction, controllerPointer, AsmHookBehaviour.ExecuteAfter).Activate();

                _utils.Log("Successfully hooked into input functions");
                _battle = new BattleControls(_utils, _baseAddress, _config, _memory, _hooks);
            }
            catch (Exception e)
            {
                _utils.LogError($"Error hooking into input functions. Unloading mod", e);
                Suspend();
                return;
            } 
        }

        public void Suspend()
        {
            _keyboardHook?.Disable();
            _controllerHook?.Disable();
        }
        public void Resume()
        {
            _keyboardHook?.Enable();
            _controllerHook?.Enable();
        }

        public void UpdateConfiguration(Config configuration)
        {
            _config = configuration;
        }

        // Function that reads all inputs
        private void InputHappened(int input, bool risingEdge, bool keyboard)
        {
            _battle.SendInput(input, risingEdge);

        }

        // Switches keyboard inputs to match controller ones
        private void KeyboardInputHappened(int input)
        {
            // Switch cross and circle as it is opposite compared to controller
            if (input == (int)Input.Circle) input = (int)Input.Cross;
            else if (input == (int)Input.Cross) input = (int)Input.Circle;
            // Decide whether the input needs to be processed (only rising edge for now)
            if (RisingEdge(input, lastKeyboardInput))
                InputHappened(input, true, true);
            else if (FallingEdge(input, lastKeyboardInput))
                InputHappened(input, false, true);
            // Update the last inputs
            lastKeyboardInput = input;
            if (controllerInputHistory[0] == 0)
            {
                if (lastControllerInput != 0)
                    InputHappened(input, false, false);
                lastControllerInput = 0;
            }
            _utils.ArrayPush(controllerInputHistory, 0);
        }

        // Gets controller inputs
        private void ControllerInputHappened(int input)
        {
            //_utils.LogDebug($"Debug input was {input}, lastInput: {lastControllerInputs[0]}, {lastControllerInputs[1]}, {lastControllerInputs[2]} ");
            // Decide whether the input needs to be processed (only rising edge for now)
            _utils.ArrayPush(controllerInputHistory, input);
            input = GetControllerInput();

            if (RisingEdge(input, lastControllerInput))
                InputHappened(input, true, false);
            // Update the last input
            lastControllerInput = input;
        }

        // Checks if an input was rising edge/falling edge (the button was just pressed/just released)
        private bool RisingEdge(int currentInput, int lastInput)
        {
            if (currentInput == 0) return false;
            return currentInput != lastInput;
        }
        private bool FallingEdge(int currentInput, int lastInput)
        {
            return lastInput != 0 && currentInput != lastInput;
        }
        // Get controller input
        private int GetControllerInput()
        {
            int inputCombo = 0;
            int lastInput = 0;
            // Work out the pressed buttons
            for (int i = 0; i < controllerInputHistory.Length; i++)
            {
                int input = controllerInputHistory[i];
                // Start of a combo
                if (lastInput == 0 && input != 0)
                    inputCombo = input;
                // Middle of a combo
                else if (lastInput != 0 && input != 0)
                    inputCombo += input;
                // End of a combo
                else if (input == 0 && lastInput != 0 && i != 1)
                    break;
                // Two 0's in a row means the combo must be over
                else if (i != 0 && input == 0 && lastInput == 0)
                    break;
                lastInput = input;
            }
            return inputCombo;
        }

        // Works out what inputs were pressed if a combination of keys were pressed (only applicable to keyboard)
        private List<Input> GetInputsFromCombo(int inputCombo, bool keyboard)
        {
            // List of the inputs found in the combo
            List<Input> foundInputs = new List<Input>();
            // Check if the input isn't actually a combo, if so we can directly return it
            if (Enum.IsDefined(typeof(Input), inputCombo))
            {

                if (keyboard && inputCombo == (int)Input.Circle)
                    foundInputs.Add(Input.Cross);
                else if (keyboard && inputCombo == (int)Input.Cross)
                    foundInputs.Add(Input.Circle);
                else
                    foundInputs.Add((Input)inputCombo);
                return foundInputs;
            }

            // Get all possible inputs as an array
            var possibleInputs = Enum.GetValues(typeof(Input));
            // Reverse the array so it goes from highest input value to smallest
            Array.Reverse(possibleInputs);
            // Go through each possible input to find out which are a part of the key combo
            foreach (int possibleInput in possibleInputs)
            {
                // If input - possibleInput is greater than 0 that input must be a part of the combination
                // This is the same idea as converting bits to decimal
                if (inputCombo - possibleInput >= 0)
                {
                    inputCombo -= possibleInput;
                    // Switch cross and circle if it is one of them as it is opposite compared to controller
                    if (possibleInput == (int)Input.Circle)
                        foundInputs.Add(Input.Cross);
                    else if (possibleInput == (int)Input.Cross)
                        foundInputs.Add(Input.Circle);
                    else
                        foundInputs.Add((Input)possibleInput);
                }
            }
            if (foundInputs.Count > 0)
                _utils.LogDebug($"Input combo was {string.Join(", ", foundInputs)}");
            return foundInputs;
        }

        // Checks if the desired input is a part of the combo
        // (so individual keyboard inputs aren't missed if they were pressed with other keys like pressing esc whilst running)
        private bool InputInCombo(int inputCombo, Input desiredInput, bool keyboard)
        {
            return GetInputsFromCombo(inputCombo, keyboard).Contains(desiredInput);
        }

        private bool InEvent()
        {
            // Get the current event
            _memory.SafeRead((IntPtr)_baseAddress + 0x9CAB94, out short[] currentEvent, 3);
            // If either the event major or minor isn't 0 we are in an event otherwise we're not
            return currentEvent[0] != 0 || currentEvent[2] != 0;
        }

        [Function(Register.ebx, Register.edi, StackCleanup.Callee)]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void KeyboardInputFunction(int input);

        [Function(Register.eax, Register.edi, StackCleanup.Callee)]
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void ControllerInputFunction(int input);
    }
}
