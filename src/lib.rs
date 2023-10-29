#![no_std]
#![feature(type_alias_impl_trait, const_async_blocks)]
#![warn(
    clippy::complexity,
    clippy::correctness,
    clippy::perf,
    clippy::style,
    clippy::undocumented_unsafe_blocks,
    rust_2018_idioms
)]

use asr::{
    file_format::pe::{self, MachineType},
    future::{next_tick, retry},
    settings::Gui,
    signature::Signature,
    string::ArrayCString,
    time::Duration,
    timer::{self, TimerState},
    watcher::Watcher,
    Address, Address32, Address64, Process,
};

asr::panic_handler!();
asr::async_main!(nightly);

const PROCESS_NAMES: &[&str] = &["Sonic Triple Trouble 16-Bit.exe"];

async fn main() {
    let mut settings = Settings::register();

    loop {
        // Hook to the target process
        let process = retry(|| PROCESS_NAMES.iter().find_map(|&name| Process::attach(name))).await;

        process
            .until_closes(async {
                // Once the target has been found and attached to, set up some default watchers
                let mut watchers = Watchers::default();

                // Perform memory scanning to look for the addresses we need
                let addresses = Addresses::init(&process).await;

                loop {
                    // Splitting logic. Adapted from OG LiveSplit:
                    // Order of execution
                    // 1. update() will always be run first. There are no conditions on the execution of this action.
                    // 2. If the timer is currently either running or paused, then the isLoading, gameTime, and reset actions will be run.
                    // 3. If reset does not return true, then the split action will be run.
                    // 4. If the timer is currently not running (and not paused), then the start action will be run.
                    settings.update();
                    update_loop(&process, &addresses, &mut watchers);

                    let timer_state = timer::state();
                    if timer_state == TimerState::Running || timer_state == TimerState::Paused {
                        if let Some(is_loading) = is_loading(&watchers, &settings) {
                            if is_loading {
                                timer::pause_game_time()
                            } else {
                                timer::resume_game_time()
                            }
                        }

                        if let Some(game_time) = game_time(&watchers, &settings) {
                            timer::set_game_time(game_time)
                        }

                        if reset(&watchers, &settings) {
                            timer::reset()
                        } else if split(&watchers, &settings) {
                            timer::split()
                        }
                    }

                    if timer::state() == TimerState::NotRunning && start(&watchers, &settings) {
                        timer::start();
                        timer::pause_game_time();

                        if let Some(is_loading) = is_loading(&watchers, &settings) {
                            if is_loading {
                                timer::pause_game_time()
                            } else {
                                timer::resume_game_time()
                            }
                        }
                    }

                    next_tick().await;
                }
            })
            .await;
    }
}

#[derive(Default)]
struct Watchers {
    state: Watcher<GameState>,
    levelid: Watcher<Acts>,
}

#[derive(Gui)]
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

struct Addresses {
    room_id: Address,
    room_id_array: Address,
    is_64_bit: bool,
}

impl Addresses {
    async fn init(process: &Process) -> Self {
        let main_module = {
            let main_module_base = retry(|| {
                PROCESS_NAMES
                    .iter()
                    .find_map(|&name| process.get_module_address(name).ok())
            })
            .await;
            let main_module_size =
                retry(|| pe::read_size_of_image(process, main_module_base)).await as u64;

            (main_module_base, main_module_size)
        };

        let is_64_bit =
            retry(|| pe::MachineType::read(process, main_module.0)).await == MachineType::X86_64;

        let room_id: Address;
        let room_id_array: Address;

        if is_64_bit {
            let sigscan = retry(|| ROOMID_SIG64.scan_process_range(process, main_module)).await;
            let ptr = sigscan + 2;
            room_id = ptr + 0x4 + retry(|| process.read::<i32>(ptr)).await;

            let sigscan = retry(|| ROOMARRAY_SIG64.scan_process_range(process, main_module)).await;
            let ptr = sigscan + 3;
            room_id_array = ptr + 0x4 + retry(|| process.read::<i32>(ptr)).await;
        } else {
            let sigscan = retry(|| ROOMID_SIG32.scan_process_range(process, main_module)).await;
            room_id = retry(|| process.read::<Address32>(sigscan + 1))
                .await
                .into();

            let sigscan = retry(|| ROOMARRAY_SIG32.scan_process_range(process, main_module)).await;
            room_id_array = retry(|| process.read::<Address32>(sigscan + 1))
                .await
                .into();
        }

        Self {
            room_id,
            room_id_array,
            is_64_bit,
        }
    }
}

fn update_loop(proc: &Process, addresses: &Addresses, watchers: &mut Watchers) {
    let room_id = match proc.read::<u32>(addresses.room_id) {
        Ok(x) => x,
        _ => 0,
    };

    let mut room_name = ArrayCString::<25>::new();

    if addresses.is_64_bit {
        if let Ok(addr) = proc.read::<Address64>(addresses.room_id_array) {
            if let Ok(addr) = proc.read::<Address64>(addr + room_id as u64 * 8) {
                if let Ok(addr) = proc.read(addr) {
                    room_name = addr;
                }
            }
        }
    } else if let Ok(addr) = proc.read::<Address32>(addresses.room_id_array) {
        if let Ok(addr) = proc.read::<Address32>(addr + room_id * 4) {
            if let Ok(addr) = proc.read(addr) {
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
        _ => match &watchers.levelid.pair {
            Some(x) => x.current,
            _ => Acts::None,
        },
    };

    let state = match room_name_bytes {
        b"rmDataSelect" => GameState::DataSelect,
        b"rmGameStart" => GameState::GameStart,
        _ => GameState::Other,
    };

    watchers.state.update_infallible(state);
    watchers.levelid.update_infallible(act);
}

fn start(watchers: &Watchers, settings: &Settings) -> bool {
    settings.start
        && watchers.state.pair.is_some_and(|val| {
            val.old == GameState::DataSelect && val.current == GameState::GameStart
        })
}

fn split(watchers: &Watchers, settings: &Settings) -> bool {
    watchers
        .levelid
        .pair
        .is_some_and(|levelid| match levelid.current {
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
        })
}

fn reset(watchers: &Watchers, settings: &Settings) -> bool {
    settings.reset
        && watchers.state.pair.is_some_and(|val| {
            val.old == GameState::DataSelect && val.current == GameState::GameStart
        })
}

fn is_loading(_watchers: &Watchers, _settings: &Settings) -> Option<bool> {
    None
}

fn game_time(_watchers: &Watchers, _settings: &Settings) -> Option<Duration> {
    None
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
