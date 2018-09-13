import * as _ from 'lodash';

const DEFAULT_LOG_NAME = 'Copay';
const DEFAULT_LOG_LEVEL = 'silent';
const LEVELS = {
    'silent': -1,
    'debug': 0,
    'info': 1,
    'log': 2,
    'warn': 3,
    'error': 4,
    'fatal': 5
  };

/**
 * A simple logger that wraps the <tt>console.log</tt> methods when available.
 *
 * Usage:
 * <pre>
 *   log = new Logger('Utils');
 *   log.setLevel('info');
 *   log.debug('Message!'); // won't show
 *   log.setLevel('debug');
 *   log.debug('Message!', 1); // will show '[debug] copay: Message!, 1'
 * </pre>
 *
 * @param name    A name for the logger. This will show up on every log call
 * @constructor
 */
export class Logger {
  private name: string = DEFAULT_LOG_NAME;
  private level: string = DEFAULT_LOG_LEVEL;

  constructor(
    name: string
  ) {
    this.name = name;
  }

  /**
   * Process logs to show in console
   * @param {string} The level name
   */
  private processLog(levelName: string, message?, ...optionalParams): string {
    if (this.level === 'silent') return;

    if (LEVELS[this.level] > LEVELS[levelName]) return;

    let str = '[' + levelName + '] - ' + this.name + ': ' + message;
    if (console[levelName]) {
      console[levelName](str, ...optionalParams);
    } else {
      console.log(message, ...optionalParams);
    }
    return str;
  }

  /**
   * Set name of log
   * @param {string} Name of logger
   */
  public setName(name: string) {
    this.name = name;
  }

  /**
   * Sets the level of a logger. A level can be any bewteen: 'debug', 'info', 'log',
   * 'warn', 'error', and 'fatal'. That order matters: if a logger's level is set to
   * 'warn', calling <tt>level.debug</tt> won't have any effect.
   * @param {string} Name of the logging level
   */
  public setLevel(level: string) {
    this.level = level;
  }

  /**
   * Log messages at the debug level.
   * @param {string} The level name
   */
  public debug(message?, ...optionalParams) {
    return this.processLog('debug', message, ...optionalParams);
  }


  /**
   * Log messages at the info level.
   * @param {string} The level name
   */
  public info(message?, ...optionalParams) {
    return this.processLog('info', message, ...optionalParams);
  }
  
  /**
   * Log messages at an intermediary level called 'log'.
   * @param {string} The level name
   */
  public log(message?, ...optionalParams) {
    return this.processLog('log', message, ...optionalParams);
  }
  
  /**
   * Log messages at the warn level.
   * @param {string} The level name
   */
  public warn(message?, ...optionalParams) {
    return this.processLog('warn', message, ...optionalParams);
  }
  
  /**
   * Log messages at the error level.
   * @param {string} The level name
   */
  public error(message?, ...optionalParams) {
    return this.processLog('error', message, ...optionalParams);
  }
  
  /**
   * Log messages at the fatal level.
   * @param {string} The level name
   */
  public fatal(message?, ...optionalParams) {
    return this.processLog('fatal', message, ...optionalParams);
  }
}
