from typing import Dict, Any, List, Optional
import os
import yaml

_glob_config: Dict[str, Any] = None

class Config:
    declassified: List[str] = []
    known_syms: Dict[str, List[int]] = []
    key: List[str] = []
    dont_follow: List[str] = []

    follow_mem_uses: bool = False

    __overridable = [
        "declassified",
        "known_syms",
        "key",
        "dont_follow",
        "follow_mem_uses",
    ]

    @staticmethod
    def get_default_config() -> str:
        cur_folder = os.path.abspath(os.path.dirname(__file__))
        return os.path.join(cur_folder, 'config.yaml')


    def __init__(self):
        pass

    @classmethod
    def init(cls, yaml_file: str) -> None:
        global _glob_config
        assert _glob_config is None # cannot initialize twice

        # Create default config
        _glob_config = Config()

        # Load YAML configuration file
        with open(yaml_file, 'r') as file:
            config = yaml.safe_load(file)

        for key, val in config.items():
            if key in cls.__overridable:
                setattr(_glob_config, key, val)
            else:
                raise KeyError(f"Configuration {key} does not exist")

    @staticmethod
    def get() -> "Config":
        global _glob_config
        return _glob_config

    @staticmethod
    def get_sym_annotation(address: str) -> tuple[Optional[str], Optional[int]]:
        global _glob_config
        for sym_name, sym_address in _glob_config.known_syms.items():
                start = sym_address[0]
                size = sym_address[1]
                if address >= start and address < start + size:
                    return sym_name, address-start
        return None, None

