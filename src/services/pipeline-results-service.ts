import * as core from '@actions/core';
import {Octokit} from '@octokit/rest';
import {DefaultArtifactClient} from '@actions/artifact';
import * as fs from 'fs/promises';
import * as Checks from '../namespaces/Checks';
import * as VeracodePipelineResult from '../namespaces/VeracodePipelineResult';
import * as VeracodePolicyResult from '../namespaces/VeracodePolicyResult';
import {Inputs, vaildateScanResultsActionInput} from '../inputs';
import {updateChecks} from './check-service';
import {getApplicationByName} from './application-service';
import {getApplicationFindings} from './findings-service';

const LINE_NUMBER_SLOP = 3; //adjust to allow for line number movement

function printResults(
  numberOfPipelineScanFindings: number,
  numberOfMitigatedFlaws: number,
  numberOfRemainingFlaws: number
): void {
  core.info(`Pipeline findings: ${numberOfPipelineScanFindings}`);
  core.info(`Mitigated findings: ${numberOfMitigatedFlaws}`);
  core.info(`Filtered pipeline findings: ${numberOfRemainingFlaws}`);
}

async function preparePipelineResultsNonWorkflowApp(inputs: Inputs): Promise<number> {
  const LINE_NUMBER_SLOP = inputs.line_number_slop; //adjust to allow for line number movement
  core.info(`LINE_NUMBER_SLOP: ${LINE_NUMBER_SLOP}`);

  const pipelineScanFlawFilter = inputs.pipeline_scan_flaw_filter;
  core.info(`Pipeline scan flaw filter: ${pipelineScanFlawFilter}`);
  const pipeline_results_file = pipelineScanFlawFilter.includes('policy')
      ? 'filtered_results.json'
      : 'results.json';
  const filtered_pipeline_results_file = 'filtered_results.json';
  // Available filter options:
  //  - all_results: Includes all pipeline scan findings, regardless of whether they violate the security policy.
  //  - policy_violations: Includes only findings from the pipeline scan that violate the security policy.
  //  - unmitigated_results: Excludes mitigated findings on the Veracode platform and includes all remaining findings, regardless of policy violations.
  //  - unmitigated_policy_violations: Includes only unmitigated findings that violate the security policy.
  //  - new_findings: Includes net new findings introduced in this commit, regardless of policy violations, excluding findings from previous scans.
  //  - new_policy_violations: Includes net new findings introduced in this commit that violate the security policy, excluding findings from previous scans.

  let findingsArray: VeracodePipelineResult.Finding[] = [];
  let veracodePipelineResult: VeracodePipelineResult.ResultsData;
  let filteredPipelineFinding: VeracodePipelineResult.Finding[] = [];
  let filteredVeracodePipelineResult: VeracodePipelineResult.ResultsData;

  try {
    const data = await fs.readFile(pipeline_results_file, 'utf-8');
    veracodePipelineResult = JSON.parse(data);
    findingsArray = veracodePipelineResult.findings;
    if (pipelineScanFlawFilter.includes('policy'))
      filteredPipelineFinding = findingsArray;
    else {
      const filteredData = await fs.readFile(filtered_pipeline_results_file, 'utf-8');
      filteredVeracodePipelineResult = JSON.parse(filteredData);
      filteredPipelineFinding = filteredVeracodePipelineResult.findings;
    }
  } catch (error) {
    core.debug(`Error reading or parsing filtered_results.json:${error}`);
    core.setFailed('Error reading or parsing pipeline scan results.');
    return -1;
  }

  core.info('############################################')
  core.info(`filteredPipelineFinding length: ${filteredPipelineFinding.length}`);

  const filePath = 'pipeline_scan_flaw_filter.json';
  const artifactName = 'Veracode Pipeline-Scan Results - Filtered findings';
  const rootDirectory = process.cwd();
  const artifactClient = new DefaultArtifactClient();

  if (findingsArray.length === 0 ||
      pipelineScanFlawFilter === 'all_results' ||
      pipelineScanFlawFilter === 'policy_violations') {
    try {
      await fs.writeFile(filePath, JSON.stringify(veracodePipelineResult, null, 2));
      await artifactClient.uploadArtifact(artifactName, [filePath], rootDirectory);
      core.info(`${artifactName} directory uploaded successfully under the artifact.`);
    } catch (error) {
      core.info(`Error while updating the ${artifactName} artifact ${error}`);
    }
    printResults(findingsArray.length, 0, findingsArray.length);
    return filteredPipelineFinding.length === 0 ? 0 : filteredPipelineFinding.length;
  }

  let policyFindings: VeracodePolicyResult.Finding[] = [];
  try {
    const application = await getApplicationByName(inputs.appname, inputs.vid, inputs.vkey);
    const applicationGuid = application.guid;
    policyFindings = await getApplicationFindings(applicationGuid, inputs.vid, inputs.vkey);
  } catch (error) {
    core.info(`No application found with name ${inputs.appname}`);
    policyFindings = [];
  }

  // for new_findings or new_policy_violations, need to filter out all existing policy findings
  let policyFindingsToExclude: VeracodePolicyResult.Finding[] = policyFindings;
  core.debug(`policyFindings findings: ${policyFindingsToExclude.length}`);
  policyFindingsToExclude.forEach((finding) => {
    core.debug(`policyFindings finding: ${JSON.stringify(finding, null, 2)}`);
    core.debug(`policyFindings finding: ${finding.finding_details.file_path}`);
    core.debug(`policyFindings finding: ${finding.finding_details.file_line_number}`);
    core.debug(`policyFindings finding: ${finding.finding_details.cwe.id}`);
    core.debug(`policyFindings finding: ${finding.finding_details.cwe.name}`);
    core.debug(`policyFindings finding: ${finding.finding_status.status}`);
    core.debug(`policyFindings finding: ${finding.finding_status.resolution}`);
    core.debug(`policyFindings finding: ${finding.finding_status.resolution_status}`);
    core.debug(`policyFindings finding: ${finding.violates_policy}`);
    core.debug(`policyFindings finding: ${finding.description}`);
    core.debug(`policyFindings finding: ${finding.issue_id}`);
  });

  // for unmitigated_results or unmitigated_policy_violations, need to filter out mitigated findings
  if (pipelineScanFlawFilter.includes('mitigated')) {
    policyFindingsToExclude = policyFindings.filter(
        (finding) =>
            finding.finding_status.status === 'CLOSED' &&
            (finding.finding_status.resolution === 'POTENTIAL_FALSE_POSITIVE' ||
                finding.finding_status.resolution === 'MITIGATED') &&
            finding.finding_status.resolution_status === 'APPROVED'
    );
  }

  core.debug(`policyFindingsToExclude findings: ${policyFindingsToExclude.length}`);
  policyFindingsToExclude.forEach((finding) => {
    core.debug(`policyFindingsToExclude finding: ${JSON.stringify(finding, null, 2)}`);
    core.debug(`policyFindingsToExclude finding: ${finding.finding_details.file_path}`);
    core.debug(`policyFindingsToExclude finding: ${finding.finding_details.file_line_number}`);
    core.debug(`policyFindingsToExclude finding: ${finding.finding_details.cwe.id}`);
    core.debug(`policyFindingsToExclude finding: ${finding.finding_details.cwe.name}`);
    core.debug(`policyFindingsToExclude finding: ${finding.finding_status.status}`);
    core.debug(`policyFindingsToExclude finding: ${finding.finding_status.resolution}`);
    core.debug(`policyFindingsToExclude finding: ${finding.finding_status.resolution_status}`);
    core.debug(`policyFindingsToExclude finding: ${finding.violates_policy}`);
    core.debug(`policyFindingsToExclude finding: ${finding.description}`);
    core.debug(`policyFindingsToExclude finding: ${finding.issue_id}`);
  });

  // Remove item in findingsArray if there are item in policyFindingsToExlcude if the file_path and
  // cwe_id and line_number are the same
  const filteredFindingsArray = findingsArray.filter((finding) => {
    return !policyFindingsToExclude.some((mitigatedFinding) => {
      if (mitigatedFinding.finding_details.file_path.charAt(0) === '/') {
        mitigatedFinding.finding_details.file_path = mitigatedFinding.finding_details.file_path.substring(1);
      }
      return (
          finding.files.source_file.file === mitigatedFinding.finding_details.file_path &&
          +finding.cwe_id === mitigatedFinding.finding_details.cwe.id &&
          Math.abs(finding.files.source_file.line - mitigatedFinding.finding_details.file_line_number) <= LINE_NUMBER_SLOP
      );
    });
  });

  core.debug(`filteredFindingsArray findings: ${filteredFindingsArray.length}`);
  filteredFindingsArray.forEach((finding) => {
    core.debug(`filteredFindingsArray finding: ${JSON.stringify(finding, null, 2)}`);
  });

  try {
    veracodePipelineResult.findings = filteredFindingsArray;
    await fs.writeFile(filePath, JSON.stringify(veracodePipelineResult, null, 2));
    await artifactClient.uploadArtifact(artifactName, [filePath], rootDirectory);
    core.info(`${artifactName} directory uploaded successfully under the artifact.`);
  } catch (error) {
    core.info(`Error while updating the ${artifactName} artifact ${error}`);
  }

  core.info('==============================================================');
  printResults(findingsArray.length, policyFindingsToExclude.length, filteredFindingsArray.length);
  for (const finding of filteredPipelineFinding) {
    core.info(`finding.issue_id: ${finding.issue_id}`);
    core.info(`finding.files.source_file.file: ${finding.files.source_file.file}`);
    core.info(`finding.files.source_file.line: ${finding.files.source_file.line}`);
  }
  for (const finding of filteredFindingsArray) {
    core.info(`finding.issue_id: ${finding.issue_id}`);
    for (const finding2 of filteredPipelineFinding) {
      core.info(`finding.issue_id: ${finding.issue_id}`);
      core.info(`finding2.issue_id: ${finding2.issue_id}`);
      core.info(`finding.files.source_file.file: ${finding.files.source_file.file}`);
      core.info(`finding2.files.source_file.file: ${finding2.files.source_file.file}`);
      core.info(`finding.files.source_file.line: ${finding.files.source_file.line}`);
      core.info(`finding2.files.source_file.line: ${finding2.files.source_file.line}`);
      if (
          finding.issue_id === finding2.issue_id &&
          finding.files.source_file.file === finding2.files.source_file.file &&
          finding.files.source_file.line === finding2.files.source_file.line
      ) {
        return 1;
      }
    }
  }
  return 0;
}

export async function preparePipelineResults(inputs: Inputs): Promise<void> {
  const workflow_app = inputs.workflow_app;
  if (!workflow_app) {
    const hasPolicyViolatedFindings = await preparePipelineResultsNonWorkflowApp(inputs) !== 0;
    core.info(`Has policy violated findings: ${hasPolicyViolatedFindings}`);
    core.info(`Fail checks on policy: ${inputs.fail_checks_on_policy}`);
    if (hasPolicyViolatedFindings && inputs.fail_checks_on_policy) {
      core.setFailed('Pipeline scan results contain policy violated findings.');
    }
    return;
  }

  const repo = inputs.source_repository.split('/');
  const ownership = {
    owner: repo[0],
    repo: repo[1],
  };

  const checkStatic: Checks.ChecksStatic = {
    owner: ownership.owner,
    repo: ownership.repo,
    check_run_id: inputs.check_run_id,
    status: Checks.Status.Completed,
  };

  const octokit = new Octokit({
    auth: inputs.token,
  });

  // When the action is preparePolicyResults, need to make sure token,
  // check_run_id and source_repository are provided
  if (!vaildateScanResultsActionInput(inputs)) {
    core.setFailed('token, check_run_id and source_repository are required.');
     await updateChecks(
      octokit,
      checkStatic,
      inputs.fail_checks_on_error ? Checks.Conclusion.Failure : Checks.Conclusion.Success,
      [],
      'Token, check_run_id and source_repository are required.',
    );
    return;
  }

  let findingsArray: VeracodePipelineResult.Finding[] = [];
  let veracodePipelineResult;
  try {
    const data = await fs.readFile(inputs.filtered_results_file, 'utf-8');
    const parsedData: VeracodePipelineResult.ResultsData = JSON.parse(data);
    findingsArray = parsedData.findings;
    veracodePipelineResult = JSON.parse(data);
  } catch (error) {
    core.debug(`Error reading or parsing filtered_results.json:${error}`);
    core.setFailed('Error reading or parsing pipeline scan results.');
     await updateChecks(
      octokit,
      checkStatic,
      inputs.fail_checks_on_error ? Checks.Conclusion.Failure : Checks.Conclusion.Success,
      [],
      'Error reading or parsing pipeline scan results.',
    );
    return;
  }

  core.info(`Pipeline findings: ${findingsArray.length}`);

  const filePath = 'mitigated_'+inputs.filtered_results_file;
  const artifactName = 'Veracode Pipeline-Scan Results - '+inputs.filtered_results_file+' - Mitigated findings';
  const rootDirectory = process.cwd();
  const artifactClient = new DefaultArtifactClient();

  if (findingsArray.length === 0) {
    try {
      veracodePipelineResult.findings = [];
      await fs.writeFile(filePath, JSON.stringify(veracodePipelineResult, null, 2));
      await artifactClient.uploadArtifact(artifactName, [filePath], rootDirectory);
      core.info(`${artifactName} directory uploaded successfully under the artifact.`);
    } catch (error) {
      core.info(`Error while updating the ${artifactName} artifact ${error}`);
    }
    core.info('No pipeline findings, exiting and update the github check status to success');
    // update inputs.check_run_id status to success
    //await updateChecks(octokit, checkStatic, Checks.Conclusion.Success, [], 'No pipeline findings');
    return;
  }

  let policyFindings: VeracodePolicyResult.Finding[] = [];

  try {
    const application = await getApplicationByName(inputs.appname, inputs.vid, inputs.vkey);
    const applicationGuid = application.guid;
    policyFindings = await getApplicationFindings(applicationGuid, inputs.vid, inputs.vkey);
  } catch (error) {
    core.info(`No application found with name ${inputs.appname}`);
    policyFindings = [];
  }

  // What if no policy scan?
  core.info(`Policy findings: ${JSON.stringify(policyFindings.length)}`);

  const filter_mitigated_flaws = inputs.filter_mitigated_flaws;
  let policyFindingsToExlcude: VeracodePolicyResult.Finding[] = [];

  if (filter_mitigated_flaws) {
    // filter out policy findings based on violates_policy = true and finding_status.status = "CLOSED" and
    // resolution = "POTENTIAL_FALSE_POSITIVE" or "MITIGATED" and resolution_status = "APPROVED"
    policyFindingsToExlcude = policyFindings.filter((finding) => {
      return (
        finding.violates_policy === true &&
        finding.finding_status.status === 'CLOSED' &&
        (finding.finding_status.resolution === 'POTENTIAL_FALSE_POSITIVE' ||
          finding.finding_status.resolution === 'MITIGATED') &&
        finding.finding_status.resolution_status === 'APPROVED'
      );
    });
  } else {
    policyFindingsToExlcude = policyFindings.filter((finding) => {
      return finding.violates_policy === true;
    });
  }

  core.info(`Mitigated policy findings: ${JSON.stringify(policyFindingsToExlcude.length)}`);

  // Remove item in findingsArray if there are item in policyFindingsToExlcude if the file_path and
  // cwe_id and line_number are the same
  const filteredFindingsArray = findingsArray.filter((finding) => {
    return !policyFindingsToExlcude.some((mitigatedFinding) => {
      if (mitigatedFinding.finding_details.file_path.charAt(0) === '/') {
        mitigatedFinding.finding_details.file_path = mitigatedFinding.finding_details.file_path.substring(1);
      }
      return (
        finding.files.source_file.file === mitigatedFinding.finding_details.file_path &&
        +finding.cwe_id === mitigatedFinding.finding_details.cwe.id &&
        Math.abs(finding.files.source_file.line - mitigatedFinding.finding_details.file_line_number) <= LINE_NUMBER_SLOP
      );
    });
  });

  try {
    veracodePipelineResult.findings = filteredFindingsArray;
    await fs.writeFile(filePath, JSON.stringify(veracodePipelineResult, null, 2));
    await artifactClient.uploadArtifact(artifactName, [filePath], rootDirectory);
    core.info(`${artifactName} directory uploaded successfully under the artifact.`);
  } catch (error) {
    core.info(`Error while updating the ${artifactName} artifact ${error}`);
  }

  core.info(`Filtered pipeline findings: ${filteredFindingsArray.length}`);

  if (filteredFindingsArray.length === 0) {
    core.info('No pipeline findings after filtering, exiting and update the github check status to success');
    // update inputs.check_run_id status to success
    //await updateChecks(octokit, checkStatic, Checks.Conclusion.Success, [], 'No pipeline findings');
    return;
  } else {
    // use octokit to check the language of the source repository. If it is a java project, then
    // use octokit to check if the source repository is using java maven or java gradle
    // if so, filePathPrefix = 'src/main/java/'
    const repoResponse = await octokit.repos.get(ownership);
    const language = repoResponse.data.language;
    core.info(`Source repository language: ${language}`);

    let javaMaven = false;
    if (language === 'Java') {
      let pomFileExists = false;
      let gradleFileExists = false;
      try {
        await octokit.repos.getContent({ ...ownership, path: 'pom.xml' });
        pomFileExists = true;
      } catch (error) {
        core.debug(`Error reading or parsing source repository:${error}`);
      }
      try {
        await octokit.repos.getContent({ ...ownership, path: 'build.gradle' });
        gradleFileExists = true;
      } catch (error) {
        core.debug(`Error reading or parsing source repository:${error}`);
      }
      if (pomFileExists || gradleFileExists) javaMaven = true;
    }

    core.info('Pipeline findings after filtering, continue to update the github check status');

    const annotations = getAnnotations(filteredFindingsArray, javaMaven);
    const maxNumberOfAnnotations = 50;

    //mitigated findings 
    if(filteredFindingsArray.length !== policyFindings.length ){
     // await updateChecks(octokit, checkStatic, Checks.Conclusion.Success, [], 'No pipeline findings');
     core.setFailed('Vulneribilities detected')
    }

    for (let index = 0; index < annotations.length / maxNumberOfAnnotations; index++) {
      const annotationBatch = annotations.slice(index * maxNumberOfAnnotations, (index + 1) * maxNumberOfAnnotations);
      if (annotationBatch.length > 0) {
        checkStatic.status = Checks.Status.InProgress;
        await updateChecks(
          octokit,
          checkStatic,
          undefined,
          annotationBatch,
          'Here\'s the summary of the scan result.',
        );
      }
    }
  }
}


function getAnnotations(pipelineFindings: VeracodePipelineResult.Finding[], javaMaven: boolean): Checks.Annotation[] {
  const annotations: Checks.Annotation[] = [];
  pipelineFindings.forEach(function (element) {
    if (javaMaven) {
      element.files.source_file.file = `src/main/java/${element.files.source_file.file}`;
      if (element.files.source_file.file.includes('WEB-INF'))
        element.files.source_file.file = element.files.source_file.file.replace(
          /src\/main\/java\//, // Use regular expression for precise replacement
          'src/main/webapp/',
        );
    }

    const displayMessage = element.display_text
      .replace(/<span>/g, '')
      .replace(/<\/span> /g, '\n')
      .replace(/<\/span>/g, '');
    const message =
      `Filename: ${element.files.source_file.file}\n` +
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