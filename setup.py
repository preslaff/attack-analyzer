from setuptools import setup, find_packages

setup(
    name='attack_analyzer',
    version='0.1',
    description='Log Analyzer, Clustering, and Geolocation for Fail2Ban and UFW logs',
    author='preslaff',
    packages=find_packages(),
    install_requires=[
        'pandas',
        'scikit-learn',
        'numpy',
        'matplotlib',
        'inquirer',
        'folium',
        'requests',
    ],
    entry_points={
        'console_scripts': [
            'attack-analyzer=attack_analyzer.interactive:main',  # This defines the CLI command 'attack-analyzer'
        ],
    },
)
