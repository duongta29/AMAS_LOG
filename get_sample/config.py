import configparser
from pathlib import Path


__author__ = 'KhiemDH'
__github__ = 'https://github.com/khiemdoan'
__email__ = 'doankhiem.crazy@gmail.com'


class Config:

    def __init__(self, file=''):
        if file == '':
            current_dir = Path(__file__).parent
            file = Path(current_dir, 'config.ini')
        self.read(file)

    def read(self, file):
        self._config = configparser.ConfigParser()
        self._config.read(str(file))

    def save(self, file):
        with open(file, 'w') as configfile:
            self._config.write(configfile)

    def get(self, section, option):
        try:
            return self._config.get(section, option)
        except configparser.Error:
            return ''

    def set(self, section, option, value):
        if not self._config.has_section(section):
            self._config.add_section(section)
        self._config.set(section, option, value)
