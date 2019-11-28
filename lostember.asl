/*
    Lost Ember
    Version: 0.0.2
    Author: NoTeefy
    Compatible Versions:
        GOG (PC) || W10 (functional) || W7 (untested, might not work)
        Steam (PC) || W10 (untested, might not work) || W7 (untested, might not work)
    
    AutoSplitter for "Lost Ember". An awesome indie title <3

    Some code may be inspired by some referenced scripts and their authors: Avasam, DevilSquirrel, tduva, Darkid
*/
state("LostEmber-Win64-Shipping") {}
/*
    startup{} runs when the script gets loaded
*/
startup {
    // init version & debug flag
    vars.ver = "0.0.2";
    var debugEnabled = false;

    //adds a text component
    Action<string, string> dbgDisplay = (id, text) => {
        if(debugEnabled) {
            dynamic componentSettings = timer.Layout.Components
                .Where(x => x.GetType().Name == "TextComponent")
                .Select(x => (x as dynamic).Settings)
                .FirstOrDefault(x => (x as dynamic).Text1 == id);
            if(componentSettings == null) {
                var compAssembly = Assembly.LoadFrom("Components\\LiveSplit.Text.dll");
                dynamic comp = Activator.CreateInstance(compAssembly.GetType("LiveSplit.UI.Components.TextComponent"), timer);
                timer.Layout.LayoutComponents.Add(new LiveSplit.UI.Components.LayoutComponent("LiveSplit.Text.dll", comp as LiveSplit.UI.Components.IComponent));
                
                componentSettings = comp.Settings;
                componentSettings.Text1 = id;
            }
            if (componentSettings != null) {
                componentSettings.Text2 = text;
            }
        }
	};
    vars.dbgDisplay = dbgDisplay;
    
    //deletes a text component | this is quick & dirty; needs some cleanup... but it works
    Action<String> dbgDelete = (id) => {
        if(debugEnabled) {
            dynamic componentSettings = timer.Layout.Components
                .Where(x => x.GetType().Name == "TextComponent")
                .Select(x => (x as dynamic).Settings)
                .FirstOrDefault(x => (x as dynamic).Text1 == id);
            if(componentSettings != null) {
                var list = timer.Layout.LayoutComponents;
                for(int i = 0; i < list.Count; ++i) {
                    var entry = list[i].Component;
                    if(entry.ComponentName.ToString().StartsWith(id)) {
                        list.RemoveAt(i);
                        break;
                    } 
                }
            }
        }
    };
    vars.dbgDelete = dbgDelete;
	
	// log output switch for DebugView (enables/disables debug messages)
    Action<string> dbgOut = (text) => {
        if (debugEnabled) {
			print(" «[LSTEMBR - v" + vars.ver + "]» " + text);
        }
    };
    vars.dbgOut = dbgOut;
    
    vars.dbgOut("startup{} - initialising auto-splitter");

    // define general variables 
    vars.cooldownStopwatch = new Stopwatch();
	refreshRate = 1000/500; //only run twice a second (performance friendly)

    //define signature patterns (structures / AOB)
    vars.isLoadingSP = new SigScanTarget(0,
        "3F 41 56 74 79 70 65 5F 69 ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 ??"
    );

    // define general functions
    Func<int, bool, bool, Tuple<int, bool, bool>> tc = Tuple.Create;
	vars.tc = tc; // support for tuples

    Func<SigScanTarget, int[], int, String, SortedDictionary<string, bool>, MemoryWatcher, Tuple<SigScanTarget, int[], int, String, SortedDictionary<string, bool>, MemoryWatcher>> tcStruct = Tuple.Create;
	vars.tcStruct = tcStruct; // support for structure tuples
    
	Action resetValues = () => {
        vars.watcherList = null;
        vars.watchers = new MemoryWatcherList();
		vars.initialized = false;
        vars.runStarted = false;
		vars.shouldStart = false;
		vars.shouldSplit = false;
		vars.shouldPause = false;
		vars.shouldReset = false;
	};
	vars.resetValues = resetValues; //reset all reset-dependent variables & values
	vars.resetValues();
    
    Func<ProcessModuleWow64Safe, SortedDictionary<String, Tuple<SigScanTarget, int[], int, String, SortedDictionary<string, bool>, MemoryWatcher>>, IntPtr> readMultipointer = (module, watcherToResolve) => {
        IntPtr ptrToResolve = IntPtr.Zero;

        // name of watcher and its data (tuple)
        String wName = watcherToResolve.Keys.First();
        Tuple<SigScanTarget, int[], int, String, SortedDictionary<string, bool>, MemoryWatcher> wTuple = watcherToResolve[wName];
        SortedDictionary<string, bool> flags = wTuple.Item5;

        if(!vars.cooldownStopwatch.IsRunning) { // prevent errors if the start wasn't triggered in caller method
            vars.cooldownStopwatch.Start();
        }
        var elapsed = vars.cooldownStopwatch.Elapsed.TotalMilliseconds;
        if(elapsed >= 0.0125) {
            vars.dbgOut("readMultipointer{} - sig scan starting for [" + wName + "]");
            var scanner = new SignatureScanner(vars.proc, module.BaseAddress, module.ModuleMemorySize);
            if(flags["is64Bit"]) {
            vars.dbgOut("readMultipointer{} - using x64 architecture");
            }
            else {
                vars.dbgOut("readMultipointer{} - using x86 architecture");   
            }
            ptrToResolve = (IntPtr)scanner.Scan(wTuple.Item1);
            if(ptrToResolve != IntPtr.Zero) {
                IntPtr basePointer = new IntPtr((Int64)ptrToResolve + wTuple.Item3);
                vars.dbgOut("readMultipointer{} - found base pointer for [" + wName + "] at " + basePointer.ToString("X"));
                int baseOffset = 0;
                baseOffset = Convert.ToInt32((Int64)basePointer - (Int64)module.BaseAddress);
                vars.dbgOut("readMultipointer{} - calculated baseOffset for [" + wName + "] with " + baseOffset.ToString("X"));
                if(flags["isSingle"]) { // return resolved single level pointer without a deeppointer
                    IntPtr combinedPtr = new IntPtr((Int64)basePointer + wTuple.Item2[0]);
                    vars.dbgOut("readMultipointer{} - sig scan found [" + wName + "] at " + combinedPtr.ToString("X"));
                    return combinedPtr;
                }
                DeepPointer dP = new DeepPointer(module.ToString(), baseOffset, wTuple.Item2);
                IntPtr resolvedPtr = new IntPtr();
                dP.DerefOffsets(vars.proc, out resolvedPtr);
                if(resolvedPtr != IntPtr.Zero) {
                    vars.dbgOut("readMultipointer{} - sig scan found [" + wName + "] at " + resolvedPtr.ToString("X"));
                    return resolvedPtr;
                }
                else {
                    vars.dbgOut("readMultipointer{} - sig scan failed for [" + wName + "] or returned a null-pointer");
                    return IntPtr.Zero;
                }
            }
            else {
                vars.dbgOut("readMultipointer{} - sig scan failed for [" + wName + "] or returned a null-pointer");
                return ptrToResolve;
            }
        }
        return IntPtr.Zero;
    };
    vars.readMultipointer = readMultipointer;

    Action<ProcessModuleWow64Safe> triggerInit = (module) => {
        vars.dbgOut("triggerInit{} - called with module " + module.ModuleName);
        vars.cooldownStopwatch.Start(); // starting stopwatch to make sure that the more intensive computations (sig scans etc) aren't processed too frequently
        // build watcherList
        // name, tuple( struct(AOB), multilevelpointer offsets, signature offset, type, flags(is64Bit, isSingle), MemoryWatcher object => uninitialized is null)
        var watcherList = new List<SortedDictionary<String, Tuple<SigScanTarget, int[], int, String, SortedDictionary<string, bool>, MemoryWatcher>>>(){
            new SortedDictionary<String, Tuple<SigScanTarget, int[], int, String, SortedDictionary<string, bool>, MemoryWatcher>>(){
                {"isLoading",
                    vars.tcStruct(vars.isLoadingSP, new int[]{ 0x98, 0x50, 0x28, 0x451 }, 0x17, "bool", new SortedDictionary<string, bool>(){
                        {"is64Bit", true}, 
                        {"isSingle", false},
                        {"ignoreNulls", false}
                    }, null)
                }
            }
        };
        
        // resolve pointers
        for(var i = 0; i < watcherList.Count; ++i) {
            SortedDictionary<String, Tuple<SigScanTarget, int[], int, String, SortedDictionary<string, bool>, MemoryWatcher>> watcherToBuild = watcherList[i];
            String wName = watcherToBuild.Keys.First();
            Tuple<SigScanTarget, int[], int, String, SortedDictionary<string, bool>, MemoryWatcher> wTuple = watcherToBuild[wName];
            SortedDictionary<string, bool> flags = wTuple.Item5;
            
            IntPtr resolvedPtr = vars.readMultipointer(module, watcherToBuild);
            if(resolvedPtr != IntPtr.Zero || flags["ignoreNulls"]) {
                MemoryWatcher memoryWatcher;
                switch(wTuple.Item4) {
                    case "bool":
                        memoryWatcher = new MemoryWatcher<bool>(resolvedPtr);
                        break;
                    case "byte":
                        memoryWatcher = new MemoryWatcher<byte>(resolvedPtr);
                        break;
                    case "int":
                        memoryWatcher = new MemoryWatcher<int>(resolvedPtr);
                        break;
                    case "Vector3f":
                        memoryWatcher = new MemoryWatcher<Vector3f>(resolvedPtr);
                        break;
                    default:
                        memoryWatcher = new MemoryWatcher<int>(resolvedPtr);
                        break;
                }
                wTuple = vars.tcStruct(wTuple.Item1, wTuple.Item2, wTuple.Item3, wTuple.Item4, wTuple.Item5, memoryWatcher);
                watcherList[i] = new SortedDictionary<string, Tuple<SigScanTarget, int[], int, String, SortedDictionary<string, bool>, MemoryWatcher>>(){
                    {wName, wTuple}
                };
                vars.watchers.Add(memoryWatcher);
            }
            else {
                throw new Exception("triggerInit{} - pointer failed or returned a null. " + "Initialization is not done yet!");
            }
        }

        // save watcherList to global scope
        vars.watcherList = watcherList;
        vars.dbgOut("triggerInit{} - done");
        vars.initialized = true;
        vars.cooldownStopwatch.Reset(); // resetting stopwatch since we don't need it to run anymore
    };
    vars.triggerInit = triggerInit;
}
/*
    shutdown{} runs when the script gets unloaded (disabling autosplitter, closing LiveSplit, changing splits)
*/
shutdown {}
/*
    init{} runs if the given process has been found (can occur multiple times during a session; if you reopen the game as an example)
*/
init {
    vars.dbgOut("init{} - attached autosplitter to game client");
	vars.dbgOut("init{} - starting to search for the ingame memory region");
	refreshRate = 1000/500;
    vars.proc = game;
    ProcessModuleWow64Safe module = modules.Single(x => String.Equals(x.ModuleName, "PxPvdSDK_x64.dll", StringComparison.OrdinalIgnoreCase));
    vars.triggerInit(module);
    vars.dbgOut("init{} - done");
    refreshRate = 1000/7; // set cycle to refresh every 7ms
}
/*
    exit{} runs when the attached process exits/dies
*/
exit {}
/*
    update{} always runs
    return false => prevents isLoading{}, gameTime{}, reset{}
*/
update {
    if(vars.initialized) {
		refreshRate = 1000/7; // set cycle to refresh every 7ms
		vars.watchers.UpdateAll(game);
        for(int i = 0; i < vars.watcherList.Count; ++i) {
            SortedDictionary<String, Tuple<SigScanTarget, int[], int, String, SortedDictionary<string, bool>, MemoryWatcher>> currentWatcher = vars.watcherList[i];
            String currentWatcherName = currentWatcher.Keys.First();
            Tuple<SigScanTarget, int[], int, String, SortedDictionary<string, bool>, MemoryWatcher> currentWatcherTuple = currentWatcher[currentWatcherName];
            MemoryWatcher currentWatcherMW = currentWatcherTuple.Item6;
            if(currentWatcherMW.Current != null && currentWatcherMW.Old != null) {
                if(!currentWatcherMW.Current.Equals(currentWatcherMW.Old)) {
                    vars.dbgOut("update{} - " + currentWatcherName + " changed from " + currentWatcherMW.Old + " to " + currentWatcherMW.Current);

                    /*
					GENERAL SPLITTER LOGIC
					This dynamic function passes all changed values to their corresponding cases defined with the structs in var.striggerInit
                        
                    */
                    if(currentWatcherMW.Current != null) { // ignore nulled values
                        switch(currentWatcherName) { // switch the name of the structure that has triggered a changed value
                            case "isLoading":
                                vars.shouldPause = Convert.ToBoolean(currentWatcherMW.Current); // cast won't work because MemoryWatcher doesn't inherit a boolean type
                                break;
                            default: // do nothing if not specified
                                break;
                        }
                    }
                }
            }
        }
	}
	else {/* do nothing */}   
}
/*
    isLoading{} only runs when the timer's active (will be skipped if update{}'s returning false)
    return true => pauses the GameTime-Timer till the next tick
*/
isLoading {
    return vars.shouldPause;
}
/*
    gameTime{} only runs when the timer's active (will be skipped if update{}'s returning false)
    return TimeSpan object => sets the GameTime-Timer to the passed time 
*/
gameTime {}
/*
    reset{} only runs when the timer's started or paused (will be skipped if update{}'s returning false)
    return true => triggers a reset
*/
reset {}
/*
    split{} only runs when the timer's running (and skipped if reset{} returns true)
    return true => triggers a split
*/
split {}
/*
    start{} only runs when the timer's paused
    return true => starts the timer
*/
start {}