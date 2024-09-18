from setuptools import setup, find_packages

setup(
    name='attack-analyzer',
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
            'attack-analyzer=attack-analyzer.interactive:main',  # This defines the CLI command 'log-analyzer'
        ],
    },
)
