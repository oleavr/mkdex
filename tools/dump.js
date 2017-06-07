'use strict';

const fs = require('fs');

const headerSpec = [
  ['magic',           bytes(8)],
  ['checksum',        uint],
  ['signature',       bytes(20)],
  ['fileSize',        uint],
  ['headerSize',      uint],
  ['endianTag',       uint],
  ['linkSize',        uint],
  ['linkOffset',      uint],
  ['mapOffset',       uint],
  ['stringIdsSize',   uint],
  ['stringIdsOffset', uint],
  ['typeIdsSize',     uint],
  ['typeIdsOffset',   uint],
  ['protoIdsSize',    uint],
  ['protoIdsOffset',  uint],
  ['fieldIdsSize',    uint],
  ['fieldIdsOffset',  uint],
  ['methodIdsSize',   uint],
  ['methodIdsOffset', uint],
  ['classDefsSize',   uint],
  ['classDefsOffset', uint],
  ['dataSize',        uint],
  ['dataOffset',      uint],
];

const dex = fs.readFileSync(process.argv[2]);

const header = parse(dex, headerSpec);

const {stringIdsSize, stringIdsOffset} = header.params;
const stringIdsSpec = [['stringIds', stringIdsSize, [['offset', uint]]]];
const stringIds = parse(dex, stringIdsSpec, { offset: stringIdsOffset });

const stringIdValues = stringIds.params.stringIds;
const stringSpec = [['string', utf8]];
const strings = makeArray('strings', stringIdValues.map((value, index) => {
  return parse(dex, stringSpec, { offset: value.offset });
}));

const {typeIdsSize, typeIdsOffset} = header.params;
const typeIdsSpec = [['typeIds', typeIdsSize, [['index', uint]]]];
const typeIds = parse(dex, typeIdsSpec, { offset: typeIdsOffset });

const {protoIdsSize, protoIdsOffset} = header.params;
const protoIdsSpec = [['protoIds', protoIdsSize, [
  ['shortyIndex', uint],
  ['returnTypeIndex', uint],
  ['parametersOffset', uint]
]]];
const protoIds = parse(dex, protoIdsSpec, { offset: protoIdsOffset });

const {methodIdsSize, methodIdsOffset} = header.params;
const methodIdsSpec = [['methodIds', methodIdsSize, [
  ['classIndex', ushort],
  ['protoIndex', ushort],
  ['nameIndex', uint]
]]];
const methodIds = parse(dex, methodIdsSpec, { offset: methodIdsOffset });

const {classDefsSize, classDefsOffset} = header.params;
const classDefsSpec = [
  ['classDefs', classDefsSize, [
    ['classIndex', uint],
    ['accessFlags', uint],
    ['superClassIndex', uint],
    ['interfacesOffset', uint],
    ['sourceFileIndex', uint],
    ['annotationsOffset', uint],
    ['classDataOffset', uint],
    ['staticValuesOffset', uint],
  ]]
];
const classDefs = parse(dex, classDefsSpec, { offset: classDefsOffset });

const methodSpec = [
  ['methodIndexDiff', uleb128],
  ['accessFlags', uleb128],
  ['codeOffset', uleb128]
];
const classDataSpec = [
  ['staticFieldsSize', uleb128],
  ['instanceFieldsSize', uleb128],
  ['directMethodsSize', uleb128],
  ['virtualMethodsSize', uleb128],
  ['directMethods', 'directMethodsSize', methodSpec],
  ['virtualMethods', 'virtualMethodsSize', methodSpec],
];
const classDataItems = classDefs.params.classDefs.map((def, index) => {
  return parse(dex, classDataSpec, { offset: def.classDataOffset });
});

const codeItemOffsets = classDataItems.reduce((offsets, item) => {
  []
    .concat(item.params.directMethods)
    .concat(item.params.virtualMethods)
    .forEach(method => {
      const {codeOffset} = method;
      if (codeOffset !== 0) {
        offsets.add(codeOffset);
      }
    });
  return offsets;
}, new Set());
const codeItemSpec = [
  ['registersSize', ushort],
  ['insSize', ushort],
  ['outsSize', ushort],
  ['triesSize', ushort],
  ['debugInfoOffset', uint],
  ['insnsSize', uint],
  ['insns', 'insnsSize', [
    ['insn', ushort]
  ]]
];
const codeItems = Array.from(codeItemOffsets).map(offset => {
  return parse(dex, codeItemSpec, { offset });
});

const debugInfoSpec = [
  ['lineStart', uleb128],
  ['parametersSize', uleb128],
  ['parameterNames', 'parametersSize', [
    ['nameIndex', uleb128p1]
  ]],
  ['opcodes', dwarfOpcodes]
];
const debugInfoItems = codeItems.reduce((result, codeItem) => {
  const {debugInfoOffset} = codeItem.params;
  if (debugInfoOffset !== 0) {
    result.push(parse(dex, debugInfoSpec, { offset: debugInfoOffset }));
  }
  return result;
}, []);

const {mapOffset} = header.params;
const mapSpec = [
  ['size', uint],
  ['items', 'size', [
    ['type', makeEnum(ushort, [
        0, 'TYPE_HEADER_ITEM',
        1, 'TYPE_STRING_ID_ITEM',
        2, 'TYPE_TYPE_ID_ITEM',
        3, 'TYPE_PROTO_ID_ITEM',
        5, 'TYPE_METHOD_ID_ITEM',
        6, 'TYPE_CLASS_DEF_ITEM',
        0x1000, 'TYPE_MAP_LIST',
        0x1001, 'TYPE_TYPE_LIST',
        0x1003, 'TYPE_ANNOTATION_SET_ITEM',
        0x2000, 'TYPE_CLASS_DATA_ITEM',
        0x2001, 'TYPE_CODE_ITEM',
        0x2002, 'TYPE_STRING_DATA_ITEM',
        0x2003, 'TYPE_DEBUG_INFO_ITEM',
        0x2004, 'TYPE_ANNOTATION_ITEM',
        0x2006, 'TYPE_ANNOTATIONS_DIRECTORY_ITEM'
      ])
    ],
    ['unused', ushort],
    ['size', uint],
    ['offset', uint]
  ]]
];
const map = parse(dex, mapSpec, { offset: mapOffset });

const sections = [
  ['Header', header, formatHeaderValue],
  ['String IDs', stringIds, makeStringIdFormatter(dex)],
  ['Type IDs', typeIds, makeTypeIdFormatter(dex, stringIdsOffset)],
  ['Proto IDs', protoIds],
  ['Method IDs', methodIds],
  ['Class defs', classDefs],
  ['Strings', strings],
  ['Map', map]
];
classDataItems.forEach((item, index) => {
  sections.push(['Class data for class ' + index, item]);
});
codeItems.forEach((item, index) => {
  sections.push(['Code item ' + index, item]);
});
debugInfoItems.forEach((item, index) => {
  sections.push(['Debug info item ' + index, item]);
});

addMissingSections(dex, dex.length, sections);

const lines = formatSections(sections, {
  level: 3,
  indent: '  '
});
console.log(lines.join('\n'));

function formatHeaderValue (name, value, state) {
  const [formattedValue, hints] = formatGenericValue(name, value, state);

  const {previousPrefix = null} = state;
  const prefix = derivePrefix(name);
  hints.newline = (previousPrefix !== null && prefix !== previousPrefix);
  state.previousPrefix = prefix;

  return [formattedValue, hints];
}

function derivePrefix (name) {
  let result = '';

  const length = name.length;
  for (let i = 0; i !== length; i++) {
    const c = name[i];
    if (c === c.toUpperCase()) {
      break;
    }
    result += c;
  }

  return result;
}

function makeStringIdFormatter (dex) {
  return function (name, value, state) {
    const hints = {
      collapse: true
    };

    const formattedValue = `${name} = '${readString(dex, value)}'`;

    return [formattedValue, hints];
  }
}

function makeTypeIdFormatter (dex, stringIdsOffset) {
  return function (name, value, state) {
    const hints = {
      collapse: true
    };

    const stringOffset = dex.readUInt32LE(stringIdsOffset + (value * 4));

    const formattedValue = `${name} = '${readString(dex, stringOffset)}'`;

    return [formattedValue, hints];
  }
}

function readString (data, offset) {
  const [value] = utf8(data, offset);

  return value;
}

function utf8 (data, offset) {
  let size = 0;
  while (data.readUInt8(offset + 1 + size) !== 0) {
    size++;
  }

  const value = data.slice(offset + 1, offset + 1 + size).toString('utf8');

  return [value, 1 + size + 1];
}

function dwarfOpcodes (data, offset) {
  let size = 0;
  while (data.readUInt8(offset + size) !== 0) {
    size++;
  }
  size++;

  const value = data.slice(offset, offset + size);

  return [value, size];
}


// GENERIC:

function addMissingSections (data, dataSize, sections) {
  sections.sort(compareSections);

  let previousOffset = 0;
  let end = sections.length + 1;
  for (let index = 0; index !== end; index++) {
    const isLastSection = index === end - 1;

    const section = sections[isLastSection ? index - 1 : index];
    const [, , , startOffset] = section[1].items[0];
    const endOffset = startOffset + sectionSize(section);

    let gapStart, gapSize;
    if (isLastSection) {
      gapStart = endOffset;
      gapSize = dataSize - endOffset;
    } else {
      gapStart = previousOffset;
      gapSize = startOffset - previousOffset;
    }

    if (gapSize > 0) {
      const gapSpec = [['data', bytes(gapSize)]];
      const gapSection = ['Unknown', parse(data, gapSpec, { offset: gapStart })];
      sections.splice(index, 0, gapSection);

      if (!isLastSection) {
        index++;
        end++;
      }
    }

    previousOffset = endOffset;
  }
}

function sectionSize (section) {
  const [, struct] = section;

  return structSize(struct);
}

function compareSections (a, b) {
  const [, aData] = a;
  const [, bData] = b;

  return compareItems(aData.items[0], bData.items[0]);
}

function formatSections (sections, options = {}) {
  const lines = [];

  sections.forEach(([name, data, formatter], index) => {
    if (index > 0) {
      lines.push('');
    }

    const indents = makeIndents(options);

    const rawOffset = data.items[0][3];
    const offset = (rawOffset !== 0) ? '0x' + rawOffset.toString(16) : '' + rawOffset;
    lines.push(
      indents + '//',
      indents + `// Offset ${offset}: ${name}`,
      indents + '//',
      ''
    );

    const sectionOptions = Object.assign({}, options, (formatter !== undefined) ? { formatter: formatter } : {});
    lines.push(...format(data.items, sectionOptions));
  });

  return lines;
}

function parse (data, spec, options = {}) {
  const items = [];
  const params = {};

  const struct = {
    items,
    params
  };

  let {offset = 0} = options;
  spec.forEach((fieldSpec) => {
    if (fieldSpec.length === 2) {
      const [name, parseField] = fieldSpec;

      const [value, n] = parseField(data, offset);

      items.push([name, value, data.slice(offset, offset + n), offset]);

      params[name] = value;

      offset += n;
    } else {
      const [name, countSpecifier, elementSpec] = fieldSpec;

      let count;
      if (typeof countSpecifier === 'string') {
        count = params[countSpecifier];
      } else {
        count = countSpecifier;
      }

      const elements = [];
      for (let index = 0; index !== count; index++) {
        const element = parse(data, elementSpec, { offset });

        elements.push(element);

        offset += structSize(element);
      }

      appendArray(struct, name, elements);
    }
  });

  return struct;
}

function structSize (struct) {
  return struct.items.reduce((total, item) => {
    const [, , itemData] = item;

    return total + itemData.length;
  }, 0);
}

function mergeStructs (...structs) {
  const mergedItems = [];
  const mergedParams = {};

  structs.forEach(struct => {
    const {items, params} = struct;

    mergedItems.push(...items);
    Object.assign(mergedParams, params);
  });

  mergedItems.sort(compareItems);

  return {
    items: mergedItems,
    params: mergedParams
  };
}

function compareItems (a, b) {
  const [, , , aOffset] = a;
  const [, , , bOffset] = b;

  return aOffset - bOffset;
}

function makeArray (name, structs) {
  if (structs.length === 0) {
    const result = {
      items: [],
      params: {}
    };
    result.params[name] = [];
    return result;
  }

  const items = structs.map(s => s.items);
  const chunks = items.reduce((result, structItems) => result.concat(structItems.map(([, , chunk]) => chunk)), []);
  const [, , , startOffset] = items[0][0];

  const result = {
    items: [
      [name, items, Buffer.concat(chunks), startOffset]
    ],
    params: {}
  };
  result.params[name] = structs.map(s => s.params);
  return result;
}

function appendArray (target, name, structs) {
  if (structs.length === 0) {
    return;
  }

  const {items, params} = makeArray(name, structs);

  target.items.push(items[0]);
  target.params[name] = params[name];
}

function format (items, options = {}) {
  const lines = [];

  const {
    formatter = formatGenericValue,
    level = 0,
    indent = '  ',
    collapse = false
  } = options;
  const formatterState = {};

  const indents = makeIndents(options);

  let pendingNewline = false;

  items.forEach(([name, value, data, offset]) => {
    if (pendingNewline) {
      lines.push('');
      pendingNewline = false;
    }

    if (value instanceof Array) {
      const childOptions = Object.assign({ collapse: true }, options, { level: level + 1 });
      value.forEach((child, index) => {
        lines.push(`${indents}${indent}// ${name}[${index}]`);
        lines.push(...format(child, childOptions));
      });
      return;
    }

    if (formatter !== null) {
      const [formattedValue, hints] = formatter(name, value, formatterState);

      if (collapse || hints.collapse) {
        lines.push(indents + hexify(data) + ' // ' + formattedValue);
      } else {
        lines.push(indents + '// ' + formattedValue);
        lines.push(indents + hexify(data));
      }

      if (hints.newline) {
        pendingNewline = true;
      }
    } else {
      lines.push(indents + hexify(data));
    }
  });

  return lines;
}

function makeIndents (options = {}) {
  const {
    level = 0,
    indent = '  '
  } = options;

  const result = [];
  for (let i = 0; i !== level; i++) {
    result.push(indent);
  }

  return result.join('');
}

function formatGenericValue (name, value, state) {
  const hints = {};

  let formattedValue;
  const type = typeof value;
  if (type === 'number' && name.toLowerCase().indexOf('offset') !== -1 && value !== 0) {
    formattedValue = `${name}: 0x${value.toString(16)}`;
  } else if (type === 'number' || type === 'string') {
    formattedValue = `${name}: ${value}`;
  } else {
    formattedValue = `${name}`;
  }

  return [formattedValue, hints];
}

function hexify (data) {
  const pairs = [];

  const length = data.length;
  for (let i = 0; i !== length; i++) {
    let value = data[i].toString(16);
    if (value.length === 1) {
      value = '0' + value;
    }
    value = '0x' + value;
    pairs.push(value);
  }

  return pairs.join(', ') + ',';
}

function bytes (length) {
  return function () {
    return [`<${length} bytes>`, length];
  };
}

function ushort (data, offset) {
  return [data.readUInt16LE(offset), 2];
}

function uint (data, offset) {
  return [data.readUInt32LE(offset), 4];
}

function uleb128 (data, offset) {
  let result = 0;

  let byteOffset = offset;
  let bitOffset = 0;

  let byte;
  do {
    byte = data[byteOffset++];

    const chunk = byte & 0x7f;
    result |= chunk << bitOffset;
    bitOffset += 7;
  } while ((byte & 0x80) !== 0);

  return [result, byteOffset - offset];
}

function uleb128p1 (data, offset) {
  const [value, n] = uleb128(data, offset);

  return [value - 1, n];
}

function makeEnum (type, values) {
  const numValues = values.length;
  if (numValues % 2 !== 0) {
    throw new Error('Invalid enum type spec');
  }

  const nameByValue = {};
  for (let i = 0; i !== numValues; i += 2) {
    const value = values[i];
    const name = values[i + 1];
    nameByValue[value] = name;
  }

  return function (data, offset) {
    const [value, n] = type(data, offset);

    let name = nameByValue[value];
    if (name === undefined) {
      name = '0x' + value.toString(16);
    }

    return [name, n];
  }
}
