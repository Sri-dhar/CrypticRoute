import toml
import os
import sys
from typing import Any, Dict, List, Optional, Union

CONFIG: Dict[str, Any] = {}
CONFIG_PATH: Optional[str] = None

def find_config_file() -> Optional[str]:
    """
    Attempts to find the config.toml file.
    Searches in common locations relative to the script or executable.
    """
    # 1. Check if running as a bundled executable (PyInstaller)
    if getattr(sys, 'frozen', False):
        # Prioritize checking next to the executable itself for --onefile mode
        exe_dir = os.path.dirname(sys.executable)
        potential_path = os.path.join(exe_dir, "config.toml")
        if os.path.exists(potential_path):
            return potential_path

        # Fallback for --onedir mode (data bundled inside _MEIPASS)
        base_path = sys._MEIPASS # type: ignore
    else:
        # 2. Check relative to the script's directory (development mode)
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # Project root

    potential_path = os.path.join(base_path, "config.toml")
    if os.path.exists(potential_path):
        return potential_path

    # 3. Check standard system location for packaged config
    potential_path = os.path.join('/usr/share/crypticroute', 'config.toml')
    if os.path.exists(potential_path):
        return potential_path

    # 4. Check in the current working directory (less reliable for executables)
    potential_path = os.path.join(os.getcwd(), "config.toml")
    if os.path.exists(potential_path):
        return potential_path

    # 4. Check relative to the main script file (if identifiable)
    try:
        main_script_path = os.path.dirname(os.path.abspath(sys.modules['__main__'].__file__))
        potential_path = os.path.join(main_script_path, "config.toml")
        if os.path.exists(potential_path):
            return potential_path
        # Check one level up from main script
        potential_path = os.path.join(os.path.dirname(main_script_path), "config.toml")
        if os.path.exists(potential_path):
            return potential_path
    except (AttributeError, KeyError):
        # __main__ module or __file__ might not be available
        pass

    # 5. Add other locations like /etc/crypticroute/config.toml or ~/.config/crypticroute/config.toml if needed

    return None

def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """
    Loads the configuration from the specified TOML file path.
    If no path is provided, it tries to find 'config.toml'.
    """
    global CONFIG, CONFIG_PATH
    if CONFIG: # Already loaded
        return CONFIG

    if path:
        config_path_to_load = path
    else:
        config_path_to_load = find_config_file()

    if not config_path_to_load or not os.path.exists(config_path_to_load):
        print(f"Warning: Configuration file 'config.toml' not found. Using default fallbacks may occur.", file=sys.stderr)
        CONFIG = {} # Set to empty dict if not found
        CONFIG_PATH = None
        return CONFIG

    CONFIG_PATH = config_path_to_load
    try:
        with open(CONFIG_PATH, 'r') as f:
            CONFIG = toml.load(f)
        # Convert hex strings in network section back to integers
        if 'network' in CONFIG:
            for key, value in CONFIG['network'].items():
                if isinstance(value, str) and value.startswith('0x'):
                    try:
                        CONFIG['network'][key] = int(value, 16)
                    except ValueError:
                        print(f"Warning: Invalid hexadecimal value '{value}' for key '{key}' in config.toml", file=sys.stderr)
        return CONFIG
    except toml.TomlDecodeError as e:
        print(f"Error decoding configuration file '{CONFIG_PATH}': {e}", file=sys.stderr)
        raise  # Re-raise the exception to halt execution if config is critical
    except IOError as e:
        print(f"Error reading configuration file '{CONFIG_PATH}': {e}", file=sys.stderr)
        raise # Re-raise

def get_config(section: str, key: str, default: Any = None) -> Any:
    """
    Retrieves a configuration value from a specific section.
    Returns the default value if the section or key is not found.
    Loads the config if it hasn't been loaded yet.
    """
    if not CONFIG and not CONFIG_PATH: # Attempt to load if not already loaded
        load_config()

    return CONFIG.get(section, {}).get(key, default)

# Load the configuration when the module is first imported
load_config()

# Example of how to access config values:
# from crypticroute.config_loader import get_config
# discovery_port = get_config('network', 'discovery_port', 54321) # With default
# max_chunk = get_config('network', 'max_chunk_size') # No default (returns None if not found)
