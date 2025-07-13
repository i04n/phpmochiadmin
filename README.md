# PHPMochiAdmin

An enhanced fork of [phpMiniAdmin](http://phpminiadmin.sourceforge.net/) with improved code quality and modern design while maintaining its lightweight, single-file philosophy.

![Logo](assets/logo.png)

## About

PHPMochiAdmin extends phpMiniAdmin by Oleg Savchuk with functional programming patterns, template system, and better security practices. It remains a standalone PHP script for MySQL database administration.

## Installation

1. Download the `phpmochiadmin.php` file
2. Upload it to your web server's public directory
3. Access it via your browser: `http://yoursite.com/phpmochiadmin.php`

**Security Note:** Always set a strong password using the `$ACCESS_PWD` variable in the script for production use.

## Dependencies

- PHP with `mysqli` extension enabled
- MySQL/MariaDB database server

### Installing mysqli on different systems:
- **Debian/Ubuntu**: `sudo apt-get install php-mysql`
- **Windows**: Enable `extension=php_mysqli.dll` in php.ini

## Configuration

### Basic Configuration
Edit the `phpmochiadmin.php` file and configure the database connection settings:

```php
$DBDEF=array(
    'user'=>"your_username",
    'pwd'=>"your_password", 
    'db'=>"your_database",
    'host'=>"localhost",
    'chset'=>"utf8mb4"
);
```

### External Config File (Recommended)
Create a `phpminiconfig.php` file in the same directory with your settings. This allows you to upgrade PHPMochiAdmin without losing your configuration.

Sample configurations for popular applications are available in the `samples/` directory:
- WordPress (`phpminiconfig.wordpress.php`)
- Magento (`phpminiconfig.magento.php`)
- SugarCRM (`phpminiconfig.sugarcrm.php`)
- Vtiger (`phpminiconfig.vtiger.php`)
- TYPO3 (`phpminiconfig.typo3.php`)

## Security Features

- **Access Password Protection**: Set `$ACCESS_PWD` to protect your database from unauthorized access
- **Local File Access Control**: `LOAD DATA LOCAL INFILE` is disabled by default to prevent data exfiltration
- **SSL Support**: Configure SSL connections for secure database communication
- **Multiple Server Support**: Manage multiple database servers with easy switching

## Credits and License

PHPMochiAdmin is a derivative work based on [phpMiniAdmin](http://phpminiadmin.sourceforge.net/) by Oleg Savchuk (osalabs@gmail.com).

**Original phpMiniAdmin Credits:**
- Author: [Oleg Savchuk](https://github.com/osalabs)
- Website: [osalabs.com](http://osalabs.com)
- Project: [phpMiniAdmin on SourceForge](http://phpminiadmin.sourceforge.net/)

**License:** Dual licensed under GPL v2 and MIT licenses, same as the original phpMiniAdmin project. See [opensource.org/licenses](http://opensource.org/licenses/) for full license texts.

## Contributing

We welcome contributions that enhance the functionality while maintaining the lightweight philosophy of the original project. 

## Support

For PHPMochiAdmin-specific enhancements, please use this project's issue tracker.
