import * as _ from 'lodash';

import { errorSpec } from './common/errorSpec';

let message;
let stack;

let traverseNode = function(parent, errorDefinition) {
  let NodeError = function() {
    if (_.isString(errorDefinition.message)) {
      message = format(errorDefinition.message, arguments);
    } else if (_.isFunction(errorDefinition.message)) {
      message = errorDefinition.message.apply(null, arguments);
    } else {
      throw new Error('Invalid error definition for ' + errorDefinition.name);
    }
    stack = message + '\n' + (new Error()).stack;
  };
  NodeError.prototype = Object.create(parent.prototype);
  NodeError.prototype.name = parent.prototype.name + errorDefinition.name;
  parent[errorDefinition.name] = NodeError;
  if (errorDefinition.errors) {
    childDefinitions(NodeError, errorDefinition.errors);
  }
  return NodeError;
};

let format = function(message, args) {
  return message
    .replace('{0}', args[0])
    .replace('{1}', args[1])
    .replace('{2}', args[2]);
};

let childDefinitions = function(parent, childDefinitions) {
  _.each(childDefinitions, function(childDefinition) {
    traverseNode(parent, childDefinition);
  });
};

let traverseRoot = function(parent, errorsDefinition) {
  childDefinitions(parent, errorsDefinition);
  return parent;
};

export let bwc = {
  Error: Function()
};

export function extend(spec) {
  return this.traverseNode(bwc.Error, spec);
};

export function Errors() {

  bwc.Error = function() {
    message = 'Internal error';
    stack = message + '\n' + (new Error()).stack;
  };
  bwc.Error.prototype = Object.create(Error.prototype);
  bwc.Error.prototype.name = 'bwc.Error';
 
  traverseRoot(bwc.Error, errorSpec);
}
