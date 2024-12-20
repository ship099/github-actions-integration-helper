"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.preparePipelineResults = preparePipelineResults;
const core = __importStar(require("@actions/core"));
const rest_1 = require("@octokit/rest");
const artifact_1 = require("@actions/artifact");
const fs = __importStar(require("fs/promises"));
const Checks = __importStar(require("../namespaces/Checks"));
const inputs_1 = require("../inputs");
const check_service_1 = require("./check-service");
const application_service_1 = require("./application-service");
const findings_service_1 = require("./findings-service");
const LINE_NUMBER_SLOP = 3;
async function preparePipelineResults(inputs) {
    const repo = inputs.source_repository.split('/');
    const ownership = {
        owner: repo[0],
        repo: repo[1],
    };
    const checkStatic = {
        owner: ownership.owner,
        repo: ownership.repo,
        check_run_id: inputs.check_run_id,
        status: Checks.Status.Completed,
    };
    const octokit = new rest_1.Octokit({
        auth: inputs.token,
    });
    if (!(0, inputs_1.vaildateScanResultsActionInput)(inputs)) {
        core.setFailed('token, check_run_id and source_repository are required.');
        await (0, check_service_1.updateChecks)(octokit, checkStatic, inputs.fail_checks_on_error ? Checks.Conclusion.Failure : Checks.Conclusion.Success, [], 'Token, check_run_id and source_repository are required.');
        return;
    }
    let findingsArray = [];
    let veracodePipelineResult;
    try {
        const data = await fs.readFile('filtered_results.json', 'utf-8');
        const parsedData = JSON.parse(data);
        findingsArray = parsedData.findings;
        veracodePipelineResult = JSON.parse(data);
    }
    catch (error) {
        core.debug(`Error reading or parsing filtered_results.json:${error}`);
        core.setFailed('Error reading or parsing pipeline scan results.');
        await (0, check_service_1.updateChecks)(octokit, checkStatic, inputs.fail_checks_on_error ? Checks.Conclusion.Failure : Checks.Conclusion.Success, [], 'Error reading or parsing pipeline scan results.');
        return;
    }
    core.info(`Pipeline findings: ${findingsArray.length}`);
    const filePath = 'filtered_results.json';
    const artifactName = 'Veracode Pipeline-Scan Results - Mitigated findings';
    const rootDirectory = process.cwd();
    const artifactClient = new artifact_1.DefaultArtifactClient();
    if (findingsArray.length === 0) {
        try {
            veracodePipelineResult.findings = [];
            await fs.writeFile(filePath, JSON.stringify(veracodePipelineResult, null, 2));
            await artifactClient.uploadArtifact(artifactName, [filePath], rootDirectory);
            core.info(`${artifactName} directory uploaded successfully under the artifact.`);
        }
        catch (error) {
            core.info(`Error while updating the ${artifactName} artifact ${error}`);
        }
        core.info('No pipeline findings, exiting and update the github check status to success');
        await (0, check_service_1.updateChecks)(octokit, checkStatic, Checks.Conclusion.Success, [], 'No pipeline findings');
        return;
    }
    let policyFindings = [];
    try {
        const application = await (0, application_service_1.getApplicationByName)(inputs.appname, inputs.vid, inputs.vkey);
        const applicationGuid = application.guid;
        policyFindings = await (0, findings_service_1.getApplicationFindings)(applicationGuid, inputs.vid, inputs.vkey);
    }
    catch (error) {
        core.info(`No application found with name ${inputs.appname}`);
        policyFindings = [];
    }
    core.info(`Policy findings: ${policyFindings.length}`);
    const filter_mitigated_flaws = inputs.filter_mitigated_flaws;
    let policyFindingsToExlcude = [];
    if (filter_mitigated_flaws) {
        policyFindingsToExlcude = policyFindings.filter((finding) => {
            return (finding.violates_policy === true &&
                finding.finding_status.status === 'CLOSED' &&
                (finding.finding_status.resolution === 'POTENTIAL_FALSE_POSITIVE' ||
                    finding.finding_status.resolution === 'MITIGATED') &&
                finding.finding_status.resolution_status === 'APPROVED');
        });
    }
    else {
        policyFindingsToExlcude = policyFindings.filter((finding) => {
            return finding.violates_policy === true;
        });
    }
    core.info(`Mitigated policy findings: ${policyFindingsToExlcude.length}`);
    const filteredFindingsArray = findingsArray.filter((finding) => {
        return !policyFindingsToExlcude.some((mitigatedFinding) => {
            if (mitigatedFinding.finding_details.file_path.charAt(0) === '/') {
                mitigatedFinding.finding_details.file_path = mitigatedFinding.finding_details.file_path.substring(1);
            }
            return (finding.files.source_file.file === mitigatedFinding.finding_details.file_path &&
                +finding.cwe_id === mitigatedFinding.finding_details.cwe.id &&
                Math.abs(finding.files.source_file.line - mitigatedFinding.finding_details.file_line_number) <= LINE_NUMBER_SLOP);
        });
    });
    try {
        veracodePipelineResult.findings = filteredFindingsArray;
        await fs.writeFile(filePath, JSON.stringify(veracodePipelineResult, null, 2));
        await artifactClient.uploadArtifact(artifactName, [filePath], rootDirectory);
        core.info(`${artifactName} directory uploaded successfully under the artifact.`);
    }
    catch (error) {
        core.info(`Error while updating the ${artifactName} artifact ${error}`);
    }
    core.info(`Filtered pipeline findings: ${filteredFindingsArray.length}`);
    if (filteredFindingsArray.length === 0) {
        core.info('No pipeline findings after filtering, exiting and update the github check status to success');
        await (0, check_service_1.updateChecks)(octokit, checkStatic, Checks.Conclusion.Success, [], 'No pipeline findings');
        return;
    }
    else {
        const repoResponse = await octokit.repos.get(ownership);
        const language = repoResponse.data.language;
        core.info(`Source repository language: ${language}`);
        let javaMaven = false;
        if (language === 'Java') {
            let pomFileExists = false;
            let gradleFileExists = false;
            try {
                await octokit.repos.getContent(Object.assign(Object.assign({}, ownership), { path: 'pom.xml' }));
                pomFileExists = true;
            }
            catch (error) {
                core.debug(`Error reading or parsing source repository:${error}`);
            }
            try {
                await octokit.repos.getContent(Object.assign(Object.assign({}, ownership), { path: 'build.gradle' }));
                gradleFileExists = true;
            }
            catch (error) {
                core.debug(`Error reading or parsing source repository:${error}`);
            }
            if (pomFileExists || gradleFileExists)
                javaMaven = true;
        }
        core.info('Pipeline findings after filtering, continue to update the github check status');
        const annotations = getAnnotations(filteredFindingsArray, javaMaven);
        const maxNumberOfAnnotations = 50;
        for (let index = 0; index < annotations.length / maxNumberOfAnnotations; index++) {
            const annotationBatch = annotations.slice(index * maxNumberOfAnnotations, (index + 1) * maxNumberOfAnnotations);
            if (annotationBatch.length > 0) {
                await (0, check_service_1.updateChecks)(octokit, checkStatic, inputs.fail_checks_on_policy ? Checks.Conclusion.Failure : Checks.Conclusion.Success, annotationBatch, "Here's the summary of the scan result.");
            }
        }
    }
}
function getAnnotations(pipelineFindings, javaMaven) {
    const annotations = [];
    pipelineFindings.forEach(function (element) {
        if (javaMaven) {
            element.files.source_file.file = `src/main/java/${element.files.source_file.file}`;
            if (element.files.source_file.file.includes('WEB-INF'))
                element.files.source_file.file = element.files.source_file.file.replace(/src\/main\/java\//, 'src/main/webapp/');
        }
        const displayMessage = element.display_text
            .replace(/<span>/g, '')
            .replace(/<\/span> /g, '\n')
            .replace(/<\/span>/g, '');
        const message = `Filename: ${element.files.source_file.file}\n` +
            `Line: ${element.files.source_file.line}\n` +
            `CWE: ${element.cwe_id} (${element.issue_type})\n\n${displayMessage}`;
        annotations.push({
            path: `${element.files.source_file.file}`,
            start_line: element.files.source_file.line,
            end_line: element.files.source_file.line,
            annotation_level: 'warning',
            title: element.issue_type,
            message: message,
        });
    });
    return annotations;
}
