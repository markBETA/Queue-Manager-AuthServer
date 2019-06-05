from setuptools import find_packages, setup
setup(
    name='authserver',
    version='0.0.1',
    url='https://github.com/BCN3D/Queue-Manager-AuthServer',
    license='GPL-3.0',
    author='Marc Bermejo',
    maintainer='Marc Bermejo',
    maintainer_email='epardo@fundaciocim.org',
    description='This server manages the authentication process of the Queue Manager server.',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'Flask>=1.0',
        'flask-sqlalchemy',
        'sqlalchemy',
        'marshmallow==2.15.6',
        'flask-cors',
        'flask-restplus',
        'click',
        'werkzeug',
        'eventlet',
        'requests',
        'flask-jwt-extended',
        'pymysql',
        'redis',
        'cryptography',
        'psycopg2',
        'parse'
    ]
)
