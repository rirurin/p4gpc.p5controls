using p4gpc.p5controls.Configuration;
using Reloaded.Memory.Sigscan;
using Reloaded.Memory.Sources;
using Reloaded.Mod.Interfaces;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace p4gpc.p5controls
{
    public class Utils
    {
        public Config Configuration;
        private ILogger _logger;
        public Utils(Config configuration, ILogger logger)
        {
            Configuration = configuration;
            _logger = logger;
        }

        // Input Reference Enum
        public enum Input
        {
            Select = 0x1,
            Start = 0x8,
            Up = 0x10,
            Right = 0x20,
            Down = 0x40,
            Left = 0x80,
            LB = 0x400,
            RB = 0x800,
            Triangle = 0x1000,
            Circle = 0x2000,
            Cross = 0x4000,
            Square = 0x8000
        };

        // Logging Functions
        public void LogDebug(string message)
        {
            if (Configuration.DebugEnabled)
                _logger.WriteLine($"[P5BattleControls] [DEBUG] {message}", System.Drawing.Color.Yellow);
        }

        public void Log(string message)
        {
            _logger.WriteLine($"[P5BattleControls] {message}", System.Drawing.Color.LimeGreen);
        }

        public void LogError(string message, Exception e)
        {
            _logger.WriteLine($"[P5BattleControls] [ERROR] {message}: {e.Message}", System.Drawing.Color.Red);
        }

        // Miscellaneous Functions

        // Pushes an item to the start of an array, pushes rest of array forward and deletes last element
        public void ArrayPush<T>(T[] array, T newItem)
        {
            for (int i = array.Length - 1; i > 0; i--)
            {
                array[i] = array[i - 1];
            }
            array[0] = newItem;
        }
    }
}
