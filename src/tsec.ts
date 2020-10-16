// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {Checker} from './third_party/tsetse/checker';
import * as path from 'path';
import * as ts from 'typescript';

import {ENABLED_RULES} from './rule_groups';
import {ExemptionList, parseConformanceExemptionConfig} from './tsec_lib/exemption_config';
import {ExtendedParsedCommandLine, parseTsConfigFile} from './tsec_lib/tsconfig';

const FORMAT_DIAGNOSTIC_HOST: ts.FormatDiagnosticsHost = {
  getCurrentDirectory: ts.sys.getCurrentDirectory,
  // `path.resolve` helps us eliminate relative path segments ('.' and '..').
  // `ts.formatDiagnosticsWithColorAndContext` always produce relative paths.
  getCanonicalFileName: fileName => path.resolve(fileName),
  getNewLine: () => ts.sys.newLine,
};

function countErrors(diagnostics: readonly ts.Diagnostic[]): number {
  return diagnostics.reduce(
      (sum, diag) =>
          sum + (diag.category === ts.DiagnosticCategory.Error ? 1 : 0),
      0);
}

function reportDiagnosticsWithSummary(diagnostics: readonly ts.Diagnostic[]):
    number {
  ts.sys.write(ts.formatDiagnosticsWithColorAndContext(
      diagnostics, FORMAT_DIAGNOSTIC_HOST));

  const errorCount = countErrors(diagnostics);
  if (errorCount > 0) {
    // Separate from the diagnostics with two line breaks.
    const newLine = FORMAT_DIAGNOSTIC_HOST.getNewLine();
    ts.sys.write(newLine + newLine);

    if (errorCount === 1) {
      ts.sys.write(`Found 1 conformance violation.${newLine}`);
    } else {
      ts.sys.write(`Found ${errorCount} conformance violations.${newLine}`);
    }
  }
  return errorCount;
}

function getTsConfigFilePath(projectPath?: string): string {
  let tsConfigFilePath: string;

  // TODO(b/169605827): To fully align with tsc, we should also search parent
  // directories of pwd until a tsconfig.json file is found.
  if (projectPath === undefined) projectPath = '.';

  if (ts.sys.directoryExists(projectPath)) {
    tsConfigFilePath = path.join(projectPath, 'tsconfig.json');
  } else {
    tsConfigFilePath = projectPath;
  }

  return tsConfigFilePath;
}

function isParsedCommandLine(p: ts.Program|ts.EmitAndSemanticDiagnosticsBuilderProgram|ts.ParsedCommandLine):
  p is ts.ParsedCommandLine {
  return !(p as ts.Program|ts.EmitAndSemanticDiagnosticsBuilderProgram).getCompilerOptions;
}

function isBuilderProgram(p: ts.Program|ts.EmitAndSemanticDiagnosticsBuilderProgram):
  p is ts.EmitAndSemanticDiagnosticsBuilderProgram {
  return !!(p as ts.EmitAndSemanticDiagnosticsBuilderProgram).getProgram;
}

function checkConformance(p: ts.Program|ts.EmitAndSemanticDiagnosticsBuilderProgram|ts.ParsedCommandLine) {
  // As far as we can tell till TS 4.0.3, the callback never gets a chance to
  // get an argument of type ts.ParsedCommandLine.
  if (isParsedCommandLine(p)) {
    throw new Error('unreachable');
  }

  let program: ts.Program;

  if (isBuilderProgram(p)) {
    program = p.getProgram();
  } else {
    program = p;
  }

  const diagnostics: ts.Diagnostic[] = [];

  // Try locating and parsing exemption list.
  let conformanceExemptionConfig: ExemptionList = new Map();
  const compilerOptions = program.getCompilerOptions();
  const conformanceExemptionPath = compilerOptions['conformanceExemptionPath']; 
  if (typeof conformanceExemptionPath === 'string') {
    const conformanceExemptionOrErrors =
        parseConformanceExemptionConfig(conformanceExemptionPath);

    if (Array.isArray(conformanceExemptionOrErrors)) {
      diagnostics.push(...conformanceExemptionOrErrors);
    } else {
      conformanceExemptionConfig = conformanceExemptionOrErrors;
    }
  }

  // Create all enabled rules with corresponding exemption list entries.
  const conformanceChecker = new Checker(program);
  const conformanceRules = ENABLED_RULES.map(ruleCtr => {
    const allowlistEntries = [];
    const allowlistEntry = conformanceExemptionConfig.get(ruleCtr.RULE_NAME);
    if (allowlistEntry) {
      allowlistEntries.push(allowlistEntry);
    }
    return new ruleCtr(allowlistEntries);
  });

  // Register all rules.
  for (const rule of conformanceRules) {
    rule.register(conformanceChecker);
  }

  // Run all enabled conformance checks and collect errors.
  for (const sf of program.getSourceFiles()) {
    // We don't emit errors for declarations, so might as well skip checking
    // declaration files all together.
    if (sf.isDeclarationFile) continue;
    const conformanceDiagErr = conformanceChecker.execute(sf).map(
        failure => failure.toDiagnosticWithStringifiedFixes());
    diagnostics.push(...conformanceDiagErr);
  }

  // If there are conformance errors while noEmitOnError is set, refrain from
  // emitting code.
  if (diagnostics.length !== 0 && compilerOptions.noEmitOnError === true) {
    // We have to override this flag because conformance errors are not visible
    // to the actual compiler. Without `noEmit` being set, the compiler will
    // emit JS code if no other errors are found, even though we already know
    // there are conformance violations at this point.
    program.getCompilerOptions().noEmit = true;
  }

  const result = program.emit();
  diagnostics.push(...result.diagnostics);

  reportDiagnosticsWithSummary(diagnostics);
}

function overrideCompilerOptions() {
  const compilerOptionDeclarations = (ts as any).optionDeclarations;
  if (!Array.isArray(compilerOptionDeclarations)) {
    throw new Error('Cannot access compiler option declarations');
  }
  compilerOptionDeclarations.push({
    name: "conformanceExemptionPath",
    type: "string",
    isFilePath: true,
    isTsConfigOnly: true,
    // These values are internally defined by TypeScript compiler and may change
    // over version updates.
    paramType: {
      code: 6035,
      category: ts.DiagnosticCategory.Message,
      key: 'FILE_6035',
      message: 'FILE',
    },
    category: {
      code: 6178,
      category: ts.DiagnosticCategory.Message,
      key: 'Advanced_Options_6178',
      message: 'Advanced Options',
    },
    description: {
      code: 22000,
      category: ts.DiagnosticCategory.Message,
      key: 'Path_to_the_configuration_file_of_conformance_exemptions_22000',
      message: 'Path to the configuration file of conformance exemptions.',
    },
  });
}

overrideCompilerOptions();

ts.executeCommandLine(ts.sys, checkConformance, ts.sys.args);
