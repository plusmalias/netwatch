//! Device type and brand from what a Bluetooth device advertises: its name,
//! the maker in its manufacturer data, and its services. Covers the big
//! brands plus ones common in Australia (Queensland in particular).

/// Broad device categories the UI has icons for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Phone,
    Tablet,
    Computer,
    Watch,
    Fitness,
    Headphones,
    Speaker,
    Tracker,
    Car,
    Tv,
    SmartHome,
    Lock,
    GarageDoor,
    Solar,
    Scooter,
    Printer,
    GameController,
    Health,
    Appliance,
    Sensor,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Phone => "Phone",
            Kind::Tablet => "Tablet",
            Kind::Computer => "Computer",
            Kind::Watch => "Smartwatch",
            Kind::Fitness => "Fitness tracker",
            Kind::Headphones => "Headphones",
            Kind::Speaker => "Speaker",
            Kind::Tracker => "Item tracker",
            Kind::Car => "Car",
            Kind::Tv => "TV / media",
            Kind::SmartHome => "Smart home",
            Kind::Lock => "Smart lock / door access",
            Kind::GarageDoor => "Garage door / gate opener",
            Kind::Solar => "Solar / battery",
            Kind::Scooter => "E-scooter / e-bike",
            Kind::Printer => "Printer",
            Kind::GameController => "Game controller",
            Kind::Health => "Health device",
            Kind::Appliance => "Appliance",
            Kind::Sensor => "Sensor",
        }
    }

    /// A short key the UI maps to an icon.
    pub fn key(self) -> &'static str {
        match self {
            Kind::Phone => "phone",
            Kind::Tablet => "tablet",
            Kind::Computer => "computer",
            Kind::Watch => "watch",
            Kind::Fitness => "fitness",
            Kind::Headphones => "headphones",
            Kind::Speaker => "speaker",
            Kind::Tracker => "tracker",
            Kind::Car => "car",
            Kind::Tv => "tv",
            Kind::SmartHome => "home",
            Kind::Lock => "lock",
            Kind::GarageDoor => "garage",
            Kind::Solar => "solar",
            Kind::Scooter => "scooter",
            Kind::Printer => "printer",
            Kind::GameController => "game",
            Kind::Health => "health",
            Kind::Appliance => "appliance",
            Kind::Sensor => "sensor",
        }
    }
}

use Kind::*;

/// (pattern, brand, kind). Patterns are lowercase substrings of the
/// advertised name; a leading `=` means a whole word, `^` a prefix.
/// More specific rules come first: "galaxy buds" before "galaxy".
const NAME_RULES: &[(&str, Option<&str>, Kind)] = &[
    // Apple
    ("airpods", Some("Apple"), Headphones),
    ("beats", Some("Beats (Apple)"), Headphones),
    ("powerbeats", Some("Beats (Apple)"), Headphones),
    ("iphone", Some("Apple"), Phone),
    ("ipad", Some("Apple"), Tablet),
    ("apple watch", Some("Apple"), Watch),
    ("macbook", Some("Apple"), Computer),
    ("imac", Some("Apple"), Computer),
    ("mac mini", Some("Apple"), Computer),
    ("mac studio", Some("Apple"), Computer),
    ("apple tv", Some("Apple"), Tv),
    ("homepod", Some("Apple"), Speaker),
    ("airtag", Some("Apple"), Tracker),
    // Samsung
    ("galaxy buds", Some("Samsung"), Headphones),
    ("galaxy watch", Some("Samsung"), Watch),
    ("galaxy fit", Some("Samsung"), Fitness),
    ("galaxy tab", Some("Samsung"), Tablet),
    ("galaxy book", Some("Samsung"), Computer),
    ("smarttag", Some("Samsung"), Tracker),
    ("[tv] samsung", Some("Samsung"), Tv),
    ("samsung tv", Some("Samsung"), Tv),
    ("[av] samsung", Some("Samsung"), Speaker),
    ("galaxy", Some("Samsung"), Phone),
    // Google
    ("pixel buds", Some("Google"), Headphones),
    ("pixel watch", Some("Google"), Watch),
    ("pixel tablet", Some("Google"), Tablet),
    ("pixel", Some("Google"), Phone),
    ("chromecast", Some("Google"), Tv),
    ("google home", Some("Google"), Speaker),
    ("nest audio", Some("Google"), Speaker),
    ("nest mini", Some("Google"), Speaker),
    ("nest hub", Some("Google"), SmartHome),
    ("nest", Some("Google Nest"), SmartHome),
    // Other phones popular in Australia
    ("oppo", Some("Oppo"), Phone),
    ("=reno", Some("Oppo"), Phone),
    ("find x", Some("Oppo"), Phone),
    ("oneplus", Some("OnePlus"), Phone),
    ("redmi buds", Some("Xiaomi"), Headphones),
    ("redmi watch", Some("Xiaomi"), Watch),
    ("mi band", Some("Xiaomi"), Fitness),
    ("smart band", Some("Xiaomi"), Fitness),
    ("redmi", Some("Xiaomi"), Phone),
    ("=poco", Some("Xiaomi"), Phone),
    ("xiaomi", Some("Xiaomi"), Phone),
    ("moto tag", Some("Motorola"), Tracker),
    ("moto g", Some("Motorola"), Phone),
    ("moto e", Some("Motorola"), Phone),
    ("razr", Some("Motorola"), Phone),
    ("motorola", Some("Motorola"), Phone),
    ("nokia", Some("Nokia"), Phone),
    ("huawei watch", Some("Huawei"), Watch),
    ("huawei band", Some("Huawei"), Fitness),
    ("freebuds", Some("Huawei"), Headphones),
    ("huawei", Some("Huawei"), Phone),
    ("honor", Some("Honor"), Phone),
    ("=vivo", Some("vivo"), Phone),
    ("realme", Some("realme"), Phone),
    ("nothing phone", Some("Nothing"), Phone),
    ("=ear (", Some("Nothing"), Headphones),
    // Fitness and wearables
    ("fitbit", Some("Fitbit (Google)"), Fitness),
    ("charge 5", Some("Fitbit (Google)"), Fitness),
    ("charge 6", Some("Fitbit (Google)"), Fitness),
    ("versa", Some("Fitbit (Google)"), Watch),
    ("inspire 3", Some("Fitbit (Google)"), Fitness),
    ("forerunner", Some("Garmin"), Watch),
    ("fenix", Some("Garmin"), Watch),
    ("venu", Some("Garmin"), Watch),
    ("instinct", Some("Garmin"), Watch),
    ("vivoactive", Some("Garmin"), Watch),
    ("vivosmart", Some("Garmin"), Fitness),
    ("vivomove", Some("Garmin"), Watch),
    ("garmin", Some("Garmin"), Watch),
    ("polar", Some("Polar"), Fitness),
    ("whoop", Some("Whoop"), Fitness),
    ("=oura", Some("Oura"), Fitness),
    ("amazfit", Some("Amazfit"), Watch),
    ("zepp", Some("Amazfit"), Watch),
    ("suunto", Some("Suunto"), Watch),
    ("coros", Some("Coros"), Watch),
    ("wahoo", Some("Wahoo"), Fitness),
    ("peloton", Some("Peloton"), Fitness),
    // Audio
    ("jbl", Some("JBL"), Speaker),
    ("bose", Some("Bose"), Headphones),
    ("quietcomfort", Some("Bose"), Headphones),
    ("soundlink", Some("Bose"), Speaker),
    ("wh-1000", Some("Sony"), Headphones),
    ("wf-1000", Some("Sony"), Headphones),
    ("wf-c", Some("Sony"), Headphones),
    ("wh-c", Some("Sony"), Headphones),
    ("^le_wh", Some("Sony"), Headphones),
    ("srs-", Some("Sony"), Speaker),
    ("ult field", Some("Sony"), Speaker),
    ("sennheiser", Some("Sennheiser"), Headphones),
    ("momentum", Some("Sennheiser"), Headphones),
    ("jabra", Some("Jabra"), Headphones),
    ("skullcandy", Some("Skullcandy"), Headphones),
    ("soundcore", Some("Anker Soundcore"), Headphones),
    ("marshall", Some("Marshall"), Speaker),
    ("wonderboom", Some("Ultimate Ears"), Speaker),
    ("ue boom", Some("Ultimate Ears"), Speaker),
    ("megaboom", Some("Ultimate Ears"), Speaker),
    ("sonos", Some("Sonos"), Speaker),
    ("beoplay", Some("Bang & Olufsen"), Headphones),
    ("beosound", Some("Bang & Olufsen"), Speaker),
    ("echo", Some("Amazon"), Speaker),
    ("audio-technica", Some("Audio-Technica"), Headphones),
    ("^ath-", Some("Audio-Technica"), Headphones),
    // Trackers
    ("=tile", Some("Tile"), Tracker),
    ("chipolo", Some("Chipolo"), Tracker),
    ("pebblebee", Some("Pebblebee"), Tracker),
    ("nut find", Some("Nut"), Tracker),
    // Cars common on Australian roads
    ("toyota", Some("Toyota"), Car),
    ("lexus", Some("Lexus"), Car),
    ("mazda", Some("Mazda"), Car),
    ("hyundai", Some("Hyundai"), Car),
    ("bluelink", Some("Hyundai"), Car),
    ("=kia", Some("Kia"), Car),
    ("uvo", Some("Kia"), Car),
    ("ford", Some("Ford"), Car),
    ("=sync", Some("Ford"), Car),
    ("mitsubishi", Some("Mitsubishi"), Car),
    ("subaru", Some("Subaru"), Car),
    ("nissan", Some("Nissan"), Car),
    ("honda", Some("Honda"), Car),
    ("isuzu", Some("Isuzu"), Car),
    ("tesla", Some("Tesla"), Car),
    ("=byd", Some("BYD"), Car),
    ("=mg", Some("MG"), Car),
    ("=gwm", Some("GWM"), Car),
    ("haval", Some("GWM Haval"), Car),
    ("=ldv", Some("LDV"), Car),
    ("volkswagen", Some("Volkswagen"), Car),
    ("=vw", Some("Volkswagen"), Car),
    ("audi", Some("Audi"), Car),
    ("bmw", Some("BMW"), Car),
    ("mercedes", Some("Mercedes-Benz"), Car),
    ("=mbux", Some("Mercedes-Benz"), Car),
    ("volvo", Some("Volvo"), Car),
    ("polestar", Some("Polestar"), Car),
    ("jeep", Some("Jeep"), Car),
    ("uconnect", Some("Stellantis"), Car),
    ("my car", None, Car),
    ("car multimedia", None, Car),
    ("carkit", None, Car),
    // TVs and media
    ("[tv]", None, Tv),
    ("bravia", Some("Sony"), Tv),
    ("lg tv", Some("LG"), Tv),
    ("webos", Some("LG"), Tv),
    ("[lg]", Some("LG"), Tv),
    ("hisense", Some("Hisense"), Tv),
    ("=tcl", Some("TCL"), Tv),
    ("kogan", Some("Kogan"), Tv),
    ("fire tv", Some("Amazon"), Tv),
    ("firetv", Some("Amazon"), Tv),
    ("roku", Some("Roku"), Tv),
    ("telstra tv", Some("Telstra"), Tv),
    ("fetch", Some("Fetch TV"), Tv),
    ("foxtel", Some("Foxtel"), Tv),
    ("=hubbl", Some("Foxtel Hubbl"), Tv),
    ("polaroid", Some("Polaroid"), Tv),
    // Garage doors and gates (Australian brands first)
    ("merlin", Some("Merlin"), GarageDoor),
    ("b&d", Some("B&D"), GarageDoor),
    ("bnd", Some("B&D"), GarageDoor),
    ("smartphone control", Some("B&D"), GarageDoor),
    ("=ata", Some("ATA (Automatic Technology)"), GarageDoor),
    ("gdo", None, GarageDoor),
    ("gliderol", Some("Gliderol"), GarageDoor),
    ("steel-line", Some("Steel-Line"), GarageDoor),
    ("centurion", Some("Centurion"), GarageDoor),
    ("myq", Some("Chamberlain myQ"), GarageDoor),
    ("chamberlain", Some("Chamberlain"), GarageDoor),
    ("garage", None, GarageDoor),
    ("gate", None, GarageDoor),
    ("automatic door", None, GarageDoor),
    ("door opener", None, GarageDoor),
    // Smart locks and door access
    ("nuki", Some("Nuki"), Lock),
    ("august", Some("August"), Lock),
    ("yale", Some("Yale"), Lock),
    ("lockly", Some("Lockly"), Lock),
    ("schlage", Some("Schlage"), Lock),
    ("ultraloq", Some("U-tec Ultraloq"), Lock),
    ("igloohome", Some("igloohome"), Lock),
    ("=igm", Some("igloohome"), Lock),
    ("gainsborough", Some("Gainsborough"), Lock),
    ("lockwood", Some("Lockwood"), Lock),
    ("dormakaba", Some("dormakaba"), Lock),
    ("salto", Some("Salto"), Lock),
    ("tapkey", Some("Tapkey"), Lock),
    ("smart lock", None, Lock),
    ("doorlock", None, Lock),
    // Solar inverters and home batteries (rooftop solar is everywhere in QLD)
    ("fronius", Some("Fronius"), Solar),
    ("sungrow", Some("Sungrow"), Solar),
    ("solaredge", Some("SolarEdge"), Solar),
    ("enphase", Some("Enphase"), Solar),
    ("envoy", Some("Enphase"), Solar),
    ("goodwe", Some("GoodWe"), Solar),
    ("growatt", Some("Growatt"), Solar),
    ("solax", Some("SolaX"), Solar),
    ("=sma", Some("SMA"), Solar),
    ("sunny boy", Some("SMA"), Solar),
    ("powerwall", Some("Tesla"), Solar),
    ("redback", Some("Redback"), Solar),
    ("alpha ess", Some("AlphaESS"), Solar),
    ("alphaess", Some("AlphaESS"), Solar),
    ("selectronic", Some("Selectronic"), Solar),
    ("victron", Some("Victron"), Solar),
    ("=jinko", Some("Jinko"), Solar),
    // E-scooters and e-bikes (Lime and Neuron run in Brisbane)
    ("ninebot", Some("Segway-Ninebot"), Scooter),
    ("segway", Some("Segway-Ninebot"), Scooter),
    ("mi scooter", Some("Xiaomi"), Scooter),
    ("=lime", Some("Lime"), Scooter),
    ("neuron", Some("Neuron"), Scooter),
    ("=beam", Some("Beam"), Scooter),
    ("pure air", Some("Pure Electric"), Scooter),
    ("=bosch ebike", Some("Bosch"), Scooter),
    // Smart home (incl. Bunnings/Kmart Tuya "Grid Connect" brands, LIFX from Australia)
    ("lifx", Some("LIFX"), SmartHome),
    ("hue", Some("Philips Hue"), SmartHome),
    ("arlec", Some("Arlec (Bunnings)"), SmartHome),
    ("grid connect", Some("Grid Connect (Bunnings)"), SmartHome),
    ("mirabella", Some("Mirabella Genio (Kmart)"), SmartHome),
    ("=genio", Some("Mirabella Genio (Kmart)"), SmartHome),
    ("=deta", Some("Deta (Bunnings)"), SmartHome),
    ("brilliant", Some("Brilliant Smart"), SmartHome),
    ("=hpm", Some("HPM"), SmartHome),
    ("clipsal", Some("Clipsal"), SmartHome),
    ("wiser", Some("Clipsal Wiser"), SmartHome),
    ("tuya", Some("Tuya"), SmartHome),
    ("smart life", Some("Tuya"), SmartHome),
    ("switchbot", Some("SwitchBot"), SmartHome),
    ("govee", Some("Govee"), SmartHome),
    ("^ihoment", Some("Govee"), SmartHome),
    ("meross", Some("Meross"), SmartHome),
    ("aqara", Some("Aqara"), SmartHome),
    ("yeelight", Some("Yeelight"), SmartHome),
    ("sonoff", Some("Sonoff"), SmartHome),
    ("shelly", Some("Shelly"), SmartHome),
    ("tapo", Some("TP-Link Tapo"), SmartHome),
    ("kasa", Some("TP-Link Kasa"), SmartHome),
    ("=ring", Some("Ring (Amazon)"), SmartHome),
    ("doorbell", None, SmartHome),
    ("arlo", Some("Arlo"), SmartHome),
    ("eufy", Some("eufy (Anker)"), SmartHome),
    ("swann", Some("Swann"), SmartHome),
    ("ecobee", Some("ecobee"), SmartHome),
    ("daikin", Some("Daikin"), Appliance),
    ("mitsubishi electric", Some("Mitsubishi Electric"), Appliance),
    ("fujitsu", Some("Fujitsu"), Appliance),
    // Appliances and home gadgets
    ("roomba", Some("iRobot"), Appliance),
    ("irobot", Some("iRobot"), Appliance),
    ("roborock", Some("Roborock"), Appliance),
    ("deebot", Some("Ecovacs"), Appliance),
    ("dreame", Some("Dreame"), Appliance),
    ("dyson", Some("Dyson"), Appliance),
    ("oral-b", Some("Oral-B"), Appliance),
    ("sonicare", Some("Philips Sonicare"), Appliance),
    ("thermomix", Some("Thermomix"), Appliance),
    ("breville", Some("Breville"), Appliance),
    ("weber", Some("Weber"), Sensor),
    ("igrill", Some("Weber"), Sensor),
    ("meater", Some("Meater"), Sensor),
    ("inkbird", Some("Inkbird"), Sensor),
    ("ruuvi", Some("Ruuvi"), Sensor),
    ("xiaomi thermometer", Some("Xiaomi"), Sensor),
    ("lywsd", Some("Xiaomi"), Sensor),
    ("atc_", None, Sensor),
    ("govee h5", Some("Govee"), Sensor),
    // Computers and printers
    ("surface", Some("Microsoft"), Computer),
    ("thinkpad", Some("Lenovo"), Computer),
    ("^desktop-", Some("Windows PC"), Computer),
    ("^laptop-", Some("Windows PC"), Computer),
    ("officejet", Some("HP"), Printer),
    ("deskjet", Some("HP"), Printer),
    ("laserjet", Some("HP"), Printer),
    ("hp envy", Some("HP"), Printer),
    ("^hp ", Some("HP"), Printer),
    ("pixma", Some("Canon"), Printer),
    ("canon", Some("Canon"), Printer),
    ("epson", Some("Epson"), Printer),
    ("brother", Some("Brother"), Printer),
    // Game controllers
    ("xbox", Some("Microsoft"), GameController),
    ("dualsense", Some("Sony PlayStation"), GameController),
    ("dualshock", Some("Sony PlayStation"), GameController),
    ("wireless controller", Some("Sony PlayStation"), GameController),
    ("joy-con", Some("Nintendo"), GameController),
    ("pro controller", Some("Nintendo"), GameController),
    // Health devices
    ("dexcom", Some("Dexcom"), Health),
    ("freestyle libre", Some("Abbott"), Health),
    ("=libre", Some("Abbott"), Health),
    ("omnipod", Some("Insulet"), Health),
    ("medtronic", Some("Medtronic"), Health),
    ("accu-chek", Some("Roche"), Health),
    ("omron", Some("Omron"), Health),
    ("withings", Some("Withings"), Health),
];

fn word_match(hay: &str, word: &str) -> bool {
    hay.match_indices(word).any(|(i, _)| {
        let before = hay[..i].chars().next_back();
        let after = hay[i + word.len()..].chars().next();
        !before.is_some_and(|c| c.is_alphanumeric()) && !after.is_some_and(|c| c.is_alphanumeric())
    })
}

/// Brand and kind from an advertised device name.
pub fn from_name(name: &str) -> Option<(Option<&'static str>, Kind)> {
    let n = name.to_lowercase();
    NAME_RULES.iter().find_map(|(pat, brand, kind)| {
        let hit = if let Some(w) = pat.strip_prefix('=') {
            word_match(&n, w)
        } else if let Some(p) = pat.strip_prefix('^') {
            n.starts_with(p)
        } else {
            n.contains(pat)
        };
        hit.then_some((*brand, *kind))
    })
}

/// A kind implied by the maker alone, for makers that mostly make one thing.
pub fn from_maker(maker: &str) -> Option<Kind> {
    let m = maker.to_lowercase();
    let rules: &[(&str, Kind)] = &[
        ("garmin", Watch),
        ("fitbit", Fitness),
        ("huami", Fitness),
        ("anhui huami", Fitness),
        ("zepp", Fitness),
        ("polar electro", Fitness),
        ("whoop", Fitness),
        ("oura", Fitness),
        ("bose", Headphones),
        ("jabra", Headphones),
        ("gn audio", Headphones),
        ("sennheiser", Headphones),
        ("harman", Speaker),
        ("sonos", Speaker),
        ("tile", Tracker),
        ("chipolo", Tracker),
        ("pebblebee", Tracker),
        ("signify", SmartHome),
        ("lifx", SmartHome),
        ("tuya", SmartHome),
        ("govee", SmartHome),
        ("shenzhen intellirocks", SmartHome),
        ("tesla", Car),
        ("toyota", Car),
        ("hyundai", Car),
        ("ford", Car),
        ("volkswagen", Car),
        ("bmw", Car),
        ("mercedes", Car),
        ("nuki", Lock),
        ("assa abloy", Lock),
        ("dormakaba", Lock),
        ("allegion", Lock),
        ("chamberlain", GarageDoor),
        ("fronius", Solar),
        ("sungrow", Solar),
        ("enphase", Solar),
        ("solaredge", Solar),
        ("victron", Solar),
        ("segway", Scooter),
        ("ninebot", Scooter),
        ("dexcom", Health),
        ("abbott", Health),
        ("medtronic", Health),
        ("omron", Health),
        ("ruuvi", Sensor),
        ("irobot", Appliance),
        ("procter", Appliance),
        ("dyson", Appliance),
        ("nintendo", GameController),
    ];
    rules.iter().find(|(k, _)| m.contains(k)).map(|(_, kind)| *kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_common_devices_by_name() {
        assert_eq!(from_name("Jorden's AirPods Pro"), Some((Some("Apple"), Headphones)));
        assert_eq!(from_name("Galaxy Buds2 Pro"), Some((Some("Samsung"), Headphones)));
        assert_eq!(from_name("Galaxy S24"), Some((Some("Samsung"), Phone)));
        assert_eq!(from_name("Pixel 8"), Some((Some("Google"), Phone)));
        assert_eq!(from_name("OPPO Reno10"), Some((Some("Oppo"), Phone)));
        assert_eq!(from_name("Forerunner 265"), Some((Some("Garmin"), Watch)));
        assert_eq!(from_name("[TV] Samsung 7 Series"), Some((Some("Samsung"), Tv)));
        assert_eq!(from_name("Fronius Symo"), Some((Some("Fronius"), Solar)));
        assert_eq!(from_name("Merlin MyQ"), Some((Some("Merlin"), GarageDoor)));
        assert_eq!(from_name("Nuki_2A3F"), Some((Some("Nuki"), Lock)));
        assert_eq!(from_name("Tile"), Some((Some("Tile"), Tracker)));
        assert_eq!(from_name("Toyota RAV4"), Some((Some("Toyota"), Car)));
        assert_eq!(from_name("MEATER+"), Some((Some("Meater"), Sensor)));
        assert_eq!(from_name("LIFX Mini"), Some((Some("LIFX"), SmartHome)));
    }

    #[test]
    fn whole_word_rules_avoid_false_matches() {
        // "kia" inside "Nokia" must not read as a car.
        assert_eq!(from_name("Nokia G21"), Some((Some("Nokia"), Phone)));
        // "ring" inside "Keyring" must not read as a Ring doorbell.
        assert_eq!(from_name("Keyring"), None);
        assert_eq!(from_name("MG ZS EV"), Some((Some("MG"), Car)));
        assert_eq!(from_name("Ring Video Doorbell"), Some((Some("Ring (Amazon)"), SmartHome)));
    }

    #[test]
    fn infers_kind_from_maker() {
        assert_eq!(from_maker("Garmin International"), Some(Watch));
        assert_eq!(from_maker("Tile"), Some(Tracker));
        assert_eq!(from_maker("Apple"), None);
    }
}
