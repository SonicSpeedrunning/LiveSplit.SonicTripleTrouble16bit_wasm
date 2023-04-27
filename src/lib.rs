#![no_std]

use asr::{
    signature::Signature, string::ArrayCString, time::Duration, timer, timer::TimerState,
    watcher::Watcher, Address, Process,
};

#[cfg(all(not(test), target_arch = "wasm32"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

static AUTOSPLITTER: spinning_top::Spinlock<State> = spinning_top::const_spinlock(State {
    game: None,
    watchers: Watchers {
        state: Watcher::new(),
        levelid: Watcher::new(),
    },
    settings: None,
});

struct State {
    game: Option<ProcessInfo>,
    watchers: Watchers,
    settings: Option<Settings>,
}

struct ProcessInfo {
    game: Process,
    is_64_bit: bool,
    main_module_base: Address,
    main_module_size: u64,
    addresses: Option<MemoryPtr>,
}

struct Watchers {
    state: Watcher<GameState>,
    levelid: Watcher<Acts>,
}

struct MemoryPtr {
    room_id: Address,
    room_id_array: Address,
}

#[derive(asr::Settings)]
struct Settings {
    #[default = true]
    /// AUTO START
    start: bool,
    #[default = true]
    /// AUTO RESET
    reset: bool,
    #[default = true]
    /// Zone Zero (Sonic & Tails)
    zone_zero: bool,
    #[default = true]
    /// Angel Island (Knuckles)
    angel_island: bool,
    #[default = true]
    /// Great Turquoise - Act 1
    great_turquoise_1: bool,
    #[default = true]
    /// Grest Turquoise - Act 2
    great_turquoise_2: bool,
    #[default = true]
    /// Sunset Park - Act 1
    sunset_park_1: bool,
    #[default = true]
    /// Sunset Park - Act 2
    sunset_park_2: bool,
    #[default = true]
    /// Sunset Park - Act 3
    sunset_park_3: bool,
    #[default = true]
    /// Meta Junglira - Act 1
    meta_junglira_1: bool,
    #[default = true]
    /// Meta Junglira - Act 2
    meta_junglira_2: bool,
    #[default = true]
    /// Egg Zeppelin
    egg_zeppelin: bool,
    #[default = true]
    /// Robotnik Winter - Act 1
    robotnik_winter_1: bool,
    #[default = true]
    /// Robotnik Winter - Act 2
    robotnik_winter_2: bool,
    #[default = true]
    /// Purple Palace (secret zone)
    purple_palace: bool,
    #[default = true]
    /// Tidal Plant - Act 1
    tidal_plant_1: bool,
    #[default = true]
    /// Tidal Plant - Act 2
    tidal_plant_2: bool,
    #[default = true]
    /// Tidal Plant - Act 3
    tidal_plant_3: bool,
    #[default = true]
    /// Atomic Destroyer - Act 1
    atomic_destroyer_1: bool,
    #[default = true]
    /// Atomic Destroyer - Act 1
    atomic_destroyer_2: bool,
    #[default = true]
    /// Atomic Destroyer - Act 1
    atomic_destroyer_3: bool,
    #[default = true]
    /// Final Trouble (Sonic & Tails)
    final_trouble: bool,
}

impl ProcessInfo {
    fn attach_process() -> Option<Self> {
        const PROCESS_NAMES: [&str; 1] = ["Sonic Triple Trouble 16-Bit.exe"];
        let mut proc: Option<Process> = None;
        let mut proc_name: Option<&str> = None;

        for name in PROCESS_NAMES {
            proc = Process::attach(name);
            if proc.is_some() {
                proc_name = Some(name);
                break;
            }
        }

        let game = proc?;
        let main_module_base = game.get_module_address(proc_name?).ok()?;
        let main_module_size = game.get_module_size(proc_name?).ok()?;
        let is_64_bit = ROOMID_SIG64
            .scan_process_range(&game, main_module_base, main_module_size)
            .is_some();

        Some(Self {
            game,
            is_64_bit,
            main_module_base,
            main_module_size,
            addresses: None,
        })
    }

    fn look_for_addresses(&mut self) -> Option<MemoryPtr> {
        let room_id: Address;
        let room_id_array: Address;
        let game = &self.game;

        if self.is_64_bit {
            let sigscan = ROOMID_SIG64.scan_process_range(
                &self.game,
                self.main_module_base,
                self.main_module_size,
            )?;
            let ptr = sigscan.0 + 2;
            room_id = Address(ptr + 0x4 + game.read::<u32>(Address(ptr)).ok()? as u64);

            let sigscan = ROOMARRAY_SIG64.scan_process_range(
                &self.game,
                self.main_module_base,
                self.main_module_size,
            )?;
            let ptr = sigscan.0 + 3;
            room_id_array = Address(ptr + 0x4 + game.read::<u32>(Address(ptr)).ok()? as u64);
        } else {
            let sigscan = ROOMID_SIG32.scan_process_range(
                game,
                self.main_module_base,
                self.main_module_size,
            )?;
            room_id = Address(game.read::<u32>(Address(sigscan.0 + 1)).ok()? as u64);

            let sigscan = ROOMARRAY_SIG32.scan_process_range(
                game,
                self.main_module_base,
                self.main_module_size,
            )?;
            room_id_array = Address(game.read::<u32>(Address(sigscan.0 + 1)).ok()? as u64);
        }

        Some(MemoryPtr {
            room_id,
            room_id_array,
        })
    }
}

impl State {
    fn init(&mut self) -> bool {
        if self.game.is_none() {
            self.game = ProcessInfo::attach_process()
        }

        let Some(game) = &mut self.game else {
            return false
        };

        if !game.game.is_open() {
            self.game = None;
            return false;
        }

        if game.addresses.is_none() {
            game.addresses = game.look_for_addresses()
        }

        game.addresses.is_some()
    }

    fn update(&mut self) {
        let Some(game) = &self.game else { return };
        let Some(addresses) = &game.addresses else { return };
        let proc = &game.game;

        let room_id = match proc.read::<u32>(addresses.room_id) {
            Ok(x) => x,
            _ => 0,
        };

        let mut room_name = ArrayCString::<25>::new();

        if game.is_64_bit {
            if let Ok(addr) = proc.read::<u64>(addresses.room_id_array) {
                if let Ok(addr) = proc.read::<u64>(Address(addr + room_id as u64 * 8)) {
                    if let Ok(addr) = proc.read(Address(addr)) {
                        room_name = addr;
                    }
                }
            }
        } else if let Ok(addr) = proc.read::<u32>(addresses.room_id_array) {
            if let Ok(addr) = proc.read::<u32>(Address(addr as u64 + room_id as u64 * 4)) {
                if let Ok(addr) = proc.read(Address(addr as u64)) {
                    room_name = addr;
                }
            }
        }

        let room_name_bytes = room_name.as_bytes();

        let act = match room_name_bytes {
            b"rmAIZ" | b"rmZONE0bit" | b"rmZIBbit" => Acts::AngelIsland,
            b"rmZONE0" => Acts::ZoneZero,
            b"rmGTZ1" => Acts::GreatTurquoise1,
            b"rmGTZ2" => Acts::GreatTurquoise2,
            b"rmSPZ1" => Acts::SunsetPark1,
            b"rmSPZ2" => Acts::SunsetPark2,
            b"rmSPZ3" => Acts::SunsetPark3,
            b"rmMJZ1" => Acts::MetaJunglira1,
            b"rmMJZ2" => Acts::MetaJunglira2,
            b"rmEZZ" => Acts::EggZeppelin,
            b"rmRWZ1" => Acts::RobotnikWinter1,
            b"rmRWZ_Awa" | b"rmRWZ2" => Acts::RobotnikWinter2,
            b"rmTPZ1" => Acts::TidalPlant1,
            b"rmTPZ2" => Acts::TidalPlant2,
            b"rmTPZ3" => Acts::TidalPlant3,
            b"rmADZ1" => Acts::AtomicDestroyer1,
            b"rmADZ2" => Acts::AtomicDestroyer2,
            b"rmADZ3" => Acts::AtomicDestroyer3,
            b"rmFinal" => Acts::FinalTrouble,
            b"rmPPZ" => Acts::PurplePalace,
            b"rmFinalEnding" | b"rmKnuxEnding" | b"rmKnuxEnding2" | b"rmCredits" => Acts::Credits,
            _ => match &self.watchers.levelid.pair {
                Some(x) => x.current,
                _ => Acts::None,
            },
        };

        let state = match room_name_bytes {
            b"rmDataSelect" => GameState::DataSelect,
            b"rmGameStart" => GameState::GameStart,
            _ => GameState::Other,
        };

        self.watchers.state.update(Some(state));
        self.watchers.levelid.update(Some(act));
    }

    fn start(&mut self) -> bool {
        let Some(settings) = &self.settings else { return false };
        if !settings.start {
            return false;
        }

        let Some(state) = &self.watchers.state.pair else { return false };
        state.old == GameState::DataSelect && state.current == GameState::GameStart
    }

    fn split(&mut self) -> bool {
        let Some(levelid) = &self.watchers.levelid.pair else { return false };
        let Some(settings) = &self.settings else { return false };

        match levelid.current {
            Acts::GreatTurquoise1 => {
                (settings.zone_zero && levelid.old == Acts::ZoneZero)
                    || (settings.angel_island && levelid.old == Acts::AngelIsland)
            }
            Acts::GreatTurquoise2 => {
                settings.great_turquoise_1 && levelid.old == Acts::GreatTurquoise1
            }
            Acts::SunsetPark1 => settings.great_turquoise_2 && levelid.old == Acts::GreatTurquoise2,
            Acts::SunsetPark2 => settings.sunset_park_1 && levelid.old == Acts::SunsetPark1,
            Acts::SunsetPark3 => settings.sunset_park_2 && levelid.old == Acts::SunsetPark2,
            Acts::MetaJunglira1 => settings.sunset_park_3 && levelid.old == Acts::SunsetPark3,
            Acts::MetaJunglira2 => settings.meta_junglira_1 && levelid.old == Acts::MetaJunglira1,
            Acts::EggZeppelin => settings.meta_junglira_2 && levelid.old == Acts::MetaJunglira2,
            Acts::RobotnikWinter1 => settings.egg_zeppelin && levelid.old == Acts::EggZeppelin,
            Acts::RobotnikWinter2 => {
                settings.robotnik_winter_1 && levelid.old == Acts::RobotnikWinter1
            }
            Acts::PurplePalace => {
                settings.robotnik_winter_2 && levelid.old == Acts::RobotnikWinter2
            }
            Acts::TidalPlant1 => {
                (settings.robotnik_winter_2 && levelid.old == Acts::RobotnikWinter2)
                    || (settings.purple_palace && levelid.old == Acts::PurplePalace)
            }
            Acts::TidalPlant2 => settings.tidal_plant_1 && levelid.old == Acts::TidalPlant1,
            Acts::TidalPlant3 => settings.tidal_plant_2 && levelid.old == Acts::TidalPlant2,
            Acts::AtomicDestroyer1 => settings.tidal_plant_3 && levelid.old == Acts::TidalPlant3,
            Acts::AtomicDestroyer2 => {
                settings.atomic_destroyer_1 && levelid.old == Acts::AtomicDestroyer1
            }
            Acts::AtomicDestroyer3 => {
                settings.atomic_destroyer_2 && levelid.old == Acts::AtomicDestroyer2
            }
            Acts::FinalTrouble => {
                settings.atomic_destroyer_3 && levelid.old == Acts::AtomicDestroyer3
            }
            Acts::Credits => {
                (settings.atomic_destroyer_3 && levelid.old == Acts::AtomicDestroyer3)
                    || (settings.final_trouble && levelid.old == Acts::FinalTrouble)
            }
            _ => false,
        }
    }

    fn reset(&mut self) -> bool {
        let Some(settings) = &self.settings else { return false };
        if !settings.reset {
            return false;
        }

        let Some(state) = &self.watchers.state.pair else { return false };
        state.old == GameState::DataSelect && state.current == GameState::GameStart
    }

    fn is_loading(&mut self) -> Option<bool> {
        None
    }

    fn game_time(&mut self) -> Option<Duration> {
        None
    }
}

#[no_mangle]
pub extern "C" fn update() {
    // Get access to the spinlock
    let autosplitter = &mut AUTOSPLITTER.lock();

    // Sets up the settings
    autosplitter.settings.get_or_insert_with(Settings::register);

    // Main autosplitter logic, essentially refactored from the OG LivaSplit autosplitting component.
    // First of all, the autosplitter needs to check if we managed to attach to the target process,
    // otherwise there's no need to proceed further.
    if !autosplitter.init() {
        return;
    }

    // The main update logic is launched with this
    autosplitter.update();

    // Splitting logic. Adapted from OG LiveSplit:
    // Order of execution
    // 1. update() [this is launched above] will always be run first. There are no conditions on the execution of this action.
    // 2. If the timer is currently either running or paused, then the isLoading, gameTime, and reset actions will be run.
    // 3. If reset does not return true, then the split action will be run.
    // 4. If the timer is currently not running (and not paused), then the start action will be run.
    let timer_state = timer::state();
    if timer_state == TimerState::Running || timer_state == TimerState::Paused {
        if let Some(is_loading) = autosplitter.is_loading() {
            if is_loading {
                timer::pause_game_time()
            } else {
                timer::resume_game_time()
            }
        }

        if let Some(game_time) = autosplitter.game_time() {
            timer::set_game_time(game_time)
        }

        if autosplitter.reset() {
            timer::reset()
        } else if autosplitter.split() {
            timer::split()
        }
    }

    if timer::state() == TimerState::NotRunning && autosplitter.start() {
        timer::start()
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Acts {
    AngelIsland,
    ZoneZero,
    GreatTurquoise1,
    GreatTurquoise2,
    SunsetPark1,
    SunsetPark2,
    SunsetPark3,
    MetaJunglira1,
    MetaJunglira2,
    EggZeppelin,
    RobotnikWinter1,
    RobotnikWinter2,
    PurplePalace,
    TidalPlant1,
    TidalPlant2,
    TidalPlant3,
    AtomicDestroyer1,
    AtomicDestroyer2,
    AtomicDestroyer3,
    FinalTrouble,
    Credits,
    None,
}

#[derive(Clone, Copy, PartialEq)]
enum GameState {
    DataSelect,
    GameStart,
    Other,
}

const ROOMID_SIG32: Signature<105> = Signature::new("A3 ?? ?? ?? ?? 8B 06 8B CE 57 6A 06 FF 50 ?? 6A 00 57 E8 ?? ?? ?? ?? 83 C4 08 A3 ?? ?? ?? ?? 8B 06 8B CE 57 6A 06 FF 50 ?? 6A 00 57 E8 ?? ?? ?? ?? 83 C4 08 A3 ?? ?? ?? ?? 8B 06 8B CE 57 6A 06 FF 50 ?? 6A 00 57 E8 ?? ?? ?? ?? 83 C4 08 A3 ?? ?? ?? ?? 8B 06 8B CE 57 6A 06 FF 50 ?? 6A 00 57 E8 ?? ?? ?? ?? 83 C4 08 A2");
const ROOMID_SIG64: Signature<142> = Signature::new("89 05 ?? ?? ?? ?? 48 8B 03 4C 8D 43 38 BA 06 00 00 00 48 8B CB FF 50 ?? 33 D2 48 8D 4B 38 E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 48 8B 03 4C 8D 43 38 BA 06 00 00 00 48 8B CB FF 50 ?? 33 D2 48 8D 4B 38 E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 48 8B 03 4C 8D 43 38 BA 06 00 00 00 48 8B CB FF 50 ?? 33 D2 48 8D 4B 38 E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 48 8B 03 4C 8D 43 38 BA 06 00 00 00 48 8B CB FF 50 ?? 33 D2 48 8D 4B 38 E8 ?? ?? ?? ?? 88 05");
const ROOMARRAY_SIG32: Signature<12> = Signature::new("A1 ?? ?? ?? ?? 89 1C 90 42 89 55 08");
const ROOMARRAY_SIG64: Signature<12> = Signature::new("48 89 3D ?? ?? ?? ?? 48 8B 5C 24 30");
