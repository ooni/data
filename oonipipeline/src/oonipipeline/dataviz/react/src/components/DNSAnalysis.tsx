import * as React from "react";

import { useEffect, useState, useMemo } from "react";

import { Flex, Box, Text, theme, Heading, Button } from "ooni-components"

import styled from 'styled-components'

import ReactJson from 'react-json-view'
import PacmanLoader from "react-spinners/PacmanLoader";


const DataSectionTitle = styled.p`
    font-weight: bold;
    padding: 8px 0 0;
    margin: 0;
`
const DataSectionValue = styled.p`
    font-weight: normal;
    padding: 0;
    margin: 0;
    width: 50%;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
`

const DataSectionContainer = styled.div`
    background-color: ${props => props.theme.colors.gray3};
    padding: 16px;
    margin-bottom: 16px;
`

const AnalysisTableName = styled.td`
    font-weight: bold;
    padding-right: 8px;
`

const DNSAnswersList = styled.ul`
    padding: 0px;
    margin: 0;
    list-style: none;
`

const DataSection = ({ keys, data }) => {
    console.log(data)
    return (
        <Flex flexWrap='wrap'>
            {keys.map((k) => (
                <Box width={1 / 3}>
                    <DataSectionTitle>{k}</DataSectionTitle>
                    <DataSectionValue>{data[k]}</DataSectionValue>
                </Box>
            ))}
        </Flex>
    )
}

const AnalysisTable = ({ keys, data }) => {
    return (
        <table>
            <tbody>
                {keys.map((key) => (<tr><AnalysisTableName>{key}</AnalysisTableName><td>{data[key]}</td></tr>))}
            </tbody>
        </table>
    )
}

const AnalysisElement = ({ data }) => {
    const metaKeys = [
        'report_id', 'input', 'measurement_uid', 'probe_cc', 'probe_asn',
        'measurement_start_time', 'resolver_ip', 'resolver_asn', 'resolver_cc',
        'resolver_as_org_name', 'resolver_as_cc', 'resolver_is_scrubbed',
        'resolver_asn_probe', 'resolver_as_org_name_probe',
        'dns_engine_resolver_address', 'dns_engine'
    ]

    const analysisKeys = [
        'exp_dns_failure', 'exp_dns_answers', 'exp_dns_answers_count',
    ]

    const analysisTableBoolsKeys = [
        'exp_answer_contains_bogon',
        'exp_answer_contains_matching_probe_cc',
        'exp_answer_contains_matching_probe_asn',
        'exp_answer_contains_matching_probe_as_org_name',
    ]

    const analysisTableAnswersKeys = [
        'dns_answers_all_asn_count',
        'dns_answers_ip_match_all_count',
        'dns_answers_ip_match_tls_consistent_count',
        'dns_answers_ip_match_tls_consistent_include_probe_count',
        'dns_answers_ip_match_ctrl_count',
        'dns_answers_asn_match_all_count',
        'dns_answers_asn_match_tls_consistent_count',
        'dns_answers_as_org_name_match_all_count',
        'dns_answers_as_org_name_match_tls_consistent_count',
    ]

    const analysisTableFailureKeys = [
        'failure_asn_count',
        'nxdomain_asn_count',
        'ok_asn_count',
        'ctrl_matching_failures_count',
        'ctrl_failure_count'
    ]

    const [loading, setLoading] = useState(false);
    const [rawData, setRawData] = useState(null);

    const loadRawData = async () => {
        setRawData(null)
        setLoading(true)
        try {
            let response = await fetch(`/api/_/data/dns_analysis_raw?measurement_uid=${data.measurement_uid}`);
            let json = await response.json();
            setLoading(false)
            setRawData(json)
        } catch (error) {
            console.log(error);
            setLoading(false)
            return { success: false };
        }
    }

    return (
        <DataSectionContainer>
            <Heading h={3}>{data.hostname}</Heading>
            <DataSection data={data} keys={metaKeys} />
            <hr />
            <Flex flexWrap='wrap' pb={2}>
                <Box width={1 / 3}>
                    <DataSectionTitle>exp_dns_answers</DataSectionTitle>
                    <DNSAnswersList>
                        {data['exp_dns_answers'].map((answer) => (<li>{answer[0]} - {answer[1]} - {answer[2]}</li>))}
                    </DNSAnswersList>
                </Box>
                <Box width={1 / 3}>
                    <DataSectionTitle>exp_dns_answers_count</DataSectionTitle>
                    <DataSectionValue>{data['exp_dns_answers_count']}</DataSectionValue>
                </Box>
                <Box width={1 / 3}>
                    <DataSectionTitle>exp_dns_failure</DataSectionTitle>
                    <DataSectionValue>{data['exp_dns_failure']}</DataSectionValue>
                </Box>
            </Flex>
            <Flex flexWrap='wrap'>
                <Box width={1 / 2}>
                    <AnalysisTable keys={analysisTableFailureKeys} data={data} />
                </Box>
                <Box width={1 / 2}>
                    <AnalysisTable keys={analysisTableBoolsKeys} data={data} />
                </Box>
                <Box width={1 / 2}>
                    <AnalysisTable keys={analysisTableAnswersKeys} data={data} />
                </Box>
            </Flex>
            <Button onClick={loadRawData}>Load Raw Data</Button>

            <PacmanLoader loading={loading} size={10} />
            {rawData && <ReactJson src={rawData} />}
        </DataSectionContainer>
    )
}

const DNSAnalysis = () => {
    const [analysisData, setAnalysisData] = useState([]);
    const [loading, setLoading] = useState(false);

    const fetchData = async () => {
        setLoading(true)
        try {
            let response = await fetch(`/api/_/data/dns_analysis`);
            let json = await response.json();
            setLoading(false)
            return { success: true, data: json };
        } catch (error) {
            console.log(error);
            setLoading(false)
            return { success: false };
        }
    }

    useEffect(() => {
        (async () => {
            let res = await fetchData();
            if (res.success) {
                setAnalysisData(res.data);
            }
        })();
    }, []);

    return (
        <>
            {analysisData.length == 0 && <PacmanLoader loading={loading} size={10} />}
            {analysisData &&
                analysisData.map((data) => <AnalysisElement data={data} />)
            }
        </>
    )
}

export default DNSAnalysis