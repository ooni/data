import * as React from "react";
import { useState, useEffect, useMemo, useCallback } from "react";
import { Vega } from 'react-vega';

import PacmanLoader from "react-spinners/PacmanLoader";

import styled from 'styled-components'

import { MdExpandMore, MdExpandLess, MdArrowUpward, MdArrowDownward } from "react-icons/md";

import { useTable, useSortBy, useGroupBy, useExpanded } from 'react-table'

import { createGlobalStyle, ThemeProvider } from "styled-components";

import { Flex, Box, Heading, Modal, Container, Text, theme } from "ooni-components";

const GlobalStyle = createGlobalStyle`
  * {
    text-rendering: geometricPrecision;
    box-sizing: border-box;
  }
  body, html {
    margin: 0;
    padding: 0;
    font-family: "Fira Sans";
    font-size: 14px;
    height: 100%;
    background-color: #ffffff;
  }
`;

const vegaEmbedDefaults = {
  actions: {
    export: true,
    source: true,
    editor: false,
    compiled: false,
  }
}

const ChartDomainBlockingByASN = ({ probeCC, domainName, onClick }) => {
  const [data, setData] = useState({});
  const [dataLoaded, setDataLoaded] = useState(false);

  const fetchData = async () => {
    try {
      let response = await fetch(`/api/_/viz/chart/blocking_of_domain_by_asn?probe_cc=${probeCC}&domain_name=${domainName}`);
      let json = await response.json();
      return { success: true, data: json };
    } catch (error) {
      console.log(error);
      return { success: false };
    }
  }

  useEffect(() => {
    (async () => {
      setDataLoaded(false);
      let res = await fetchData();
      if (res.success) {
        setData(res.data);
        setDataLoaded(true);
      }
    })();
  }, [probeCC, domainName]);


  const handleNewView = (view) => {
    view.addEventListener("click", (_, item) => {
      if (item) {
        onClick(item.datum.probe_asn)
      }
    })
  }

  return (
    dataLoaded ?
      <Vega spec={data} onNewView={handleNewView} {...vegaEmbedDefaults} />
      : <Text>Loading data...</Text>
  )
}

const ChartDomainBlockingInASN = ({ probeCC, domainName, probeASN }) => {
  const [data, setData] = useState({});
  const [dataLoaded, setDataLoaded] = useState(false);

  const fetchData = async () => {
    try {
      let response = await fetch(`/api/_/viz/chart/blocking_of_domain_in_asn?probe_cc=${probeCC}&domain_name=${domainName}&probe_asn=${probeASN}`);
      let json = await response.json();
      return { success: true, data: json };
    } catch (error) {
      console.log(error);
      return { success: false };
    }
  }

  useEffect(() => {
    (async () => {
      setDataLoaded(false);
      let res = await fetchData();
      if (res.success) {
        setData(res.data);
        setDataLoaded(true);
      }
    })();
  }, [probeCC, domainName, probeASN]);

  return (
    dataLoaded ?
      <Vega spec={data} {...vegaEmbedDefaults} />
      : <Text>Loading data...</Text>
  )
}

const ChartWorldMap = ({ data, onClick }) => {
  const [spec, setSpec] = useState({});
  const [dataLoaded, setDataLoaded] = useState(false);

  const fetchSpec = async () => {
    try {
      let response = await fetch(`/api/_/viz/chart/world_map`);
      let json = await response.json();
      return { success: true, data: json };
    } catch (error) {
      console.log(error);
      return { success: false };
    }
  }

  useEffect(() => {
    (async () => {
      setDataLoaded(false);
      let res = await fetchSpec();
      if (res.success) {
        setSpec(res.data);
        setDataLoaded(true);
      }
    })();
  }, [data]);


  const handleNewView = (view) => {
    view.addEventListener("click", (_, item) => {
      if (item) {
        onClick({ "cc": item.datum.probe_cc, "name": item.datum.name })
      }
    })
  }

  return (
    dataLoaded ?
      <Vega spec={spec} data={{ data: data }} onNewView={handleNewView} {...vegaEmbedDefaults} />
      : <Text>Loading data...</Text>
  )
}

const StyleCountryTable = styled.div`
  padding: 1rem;

  table {
    border-spacing: 0;
    border: 1px solid black;

    tr {
      :last-child {
        td {
          border-bottom: 0;
        }
      }
    }

    th,
    td {
      margin: 0;
      padding: 0.5rem;
      border-bottom: 1px solid black;
      border-right: 1px solid black;

      :last-child {
        border-right: 0;
      }
    }
  }
`

const CountryTable = ({ data, onDomainSelected }) => {
  const columns = useMemo(() => [
    {
      id: 'category_code',
      Header: 'Category Code',
      accessor: 'category_code'
    },
    {
      id: 'domain_name',
      Header: 'Domain',
      accessor: 'domain_name',
      aggregate: 'count',
      Aggregated: ({ value }) => `${value} domains`,
    },
    {
      id: 'blocked_asns',
      Header: 'Blocked ASNS',
      accessor: 'blocked_asns',
      aggregate: 'average',
      Aggregated: ({ value }) => `${value} (avg)`,
    },
    {
      id: 'ok_asns',
      Header: 'OK ASNS',
      accessor: 'ok_asns',
      aggregate: 'average',
      Aggregated: ({ value }) => `${value} (avg)`,
    },
  ], [])

  const initialGroupBy = useMemo(() => ["category_code"], [])
  const initialSortBy = useMemo(() => [{ "id": "category_code" }], [])

  const {
    getTableProps,
    getTableBodyProps,
    headerGroups,
    rows,
    prepareRow,
    state: { groupBy, expanded },
  } = useTable(
    {
      initialState: {
        groupBy: initialGroupBy,
        sortBy: initialSortBy
      },
      columns,
      data,
    },
    useGroupBy,
    useSortBy,
    useExpanded
  )

  const onClickCell = (cell) => {
    if (!cell.isAggregated && cell.column.id == "domain_name") {
      onDomainSelected(cell.value)
    }
  }

  return (
    <StyleCountryTable>
      <table {...getTableProps()}>
        <thead>
          {headerGroups.map(headerGroup => (
            <tr {...headerGroup.getHeaderGroupProps()}>
              {headerGroup.headers.map(column => (
                // Add the sorting props to control sorting. For this example
                // we can add them into the header props
                <th {...column.getHeaderProps(column.getSortByToggleProps())}>
                  {column.render('Header')}
                  {/* Add a sort direction indicator */}
                  <span>
                    {column.isSorted
                      ? column.isSortedDesc
                        ? <MdArrowDownward />
                        : <MdArrowUpward />
                      : ''}
                  </span>
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody {...getTableBodyProps()}>
          {rows.map(
            (row, i) => {
              prepareRow(row);
              return (
                <tr {...row.getRowProps()}>
                  {row.cells.map(cell => {
                    return (
                      <td
                        onClick={() => onClickCell(cell)}
                        {...cell.getCellProps()}
                        style={{
                          background: cell.isGrouped
                            ? theme.colors.gray2
                            : cell.isAggregated
                              ? theme.colors.gray1
                              : cell.isPlaceholder
                                ? 'white'
                                : 'white',
                        }}
                      >
                        {cell.isGrouped ? (
                          // If it's a grouped cell, add an expander and row count
                          <>
                            <span {...row.getToggleRowExpandedProps()}>
                              {row.isExpanded ? <MdExpandLess /> : <MdExpandMore />}
                            </span>{' '}
                            {cell.render('Cell')} ({row.subRows.length})
                          </>
                        ) : cell.isAggregated ? (
                          // If the cell is aggregated, use the Aggregated
                          // renderer for cell
                          cell.render('Aggregated')
                        ) : cell.isPlaceholder ? null : ( // For cells with repeated values, render null
                          // Otherwise, just render the regular cell
                          cell.render('Cell')
                        )}
                      </td>
                    )
                  })}
                </tr>
              )
            }
          )}
        </tbody>
      </table >
    </StyleCountryTable>
  )

}

const StyleLoader = styled.div`
  position: fixed;
  left: 0px;
  top: 0px;
  width: 100%;
  height: 100%;
  z-index: 9999999999;
  overflow: hidden;
`

const GeneralLoader = ({ loading }) => {
  return (
    loading ?
      <StyleLoader>
        <Flex width="100%" height="50%" alignItems="center" justifyContent="center">
          <Box>
            <PacmanLoader loading={loading} size={10} />
          </Box>
          <Box pl="30px">
            <Text>...loading...</Text>
          </Box>
        </Flex>
      </StyleLoader>
      : null
  )
}

const DataViz = () => {
  const [selectedASN, setSelectedASN] = useState(null);
  const [selectedCC, setSelectedCC] = useState(null);
  const [selectedCountry, setSelectedCountry] = useState("");
  const [selectedDomainName, setSelectedDomainName] = useState(null);

  const [worldMapData, setWorldMapData] = useState([]);
  const [loading, setLoading] = useState(false)

  const [tableData, setTableData] = useState(null);

  const fetchData = async () => {
    try {
      let response = await fetch(`/api/_/viz/data/world_map`);
      let json = await response.json();
      return { success: true, data: json };
    } catch (error) {
      console.log(error);
      return { success: false };
    }
  }

  useEffect(() => {
    (async () => {
      setLoading(true);
      let res = await fetchData();
      if (res.success) {
        setWorldMapData(res.data);
        setLoading(false);
      }
    })();
  }, []);

  const onSelectedASN = (probe_asn) => {
    setSelectedASN(probe_asn)
  }

  const onSelectedCountry = ({ cc, name }) => {
    setSelectedDomainName(null)
    setSelectedASN(null)

    setSelectedCountry(name)
    setSelectedCC(cc)
  }

  useEffect(() => {
    if (selectedCC !== null) {
      const tableData = worldMapData.filter((d) => d.probe_cc == selectedCC)
      console.log("setting table data", tableData, worldMapData)
      setTableData(tableData)
    }
  }, [selectedCC])

  const onDomainSelected = (domainName) => {
    if (domainName == selectedDomainName) {
      return
    }
    setSelectedASN(null)
    setSelectedDomainName(domainName)
  }

  return (
    <Flex flexWrap="wrap">
      <Box width={1}>
        <GeneralLoader loading={loading} />
        <ChartWorldMap data={worldMapData} onClick={onSelectedCountry} />
      </Box>
      <Box width={1}>
        <Heading>{selectedCountry}</Heading>
        <Flex>
          <Box width={1 / 2}>
            {tableData && <CountryTable data={tableData} onDomainSelected={onDomainSelected} />}
          </Box>
          <Box width={1 / 2}>
            <Flex pt={2} flexWrap="wrap">
              <Box width={1}>
                {selectedASN !== null && <ChartDomainBlockingInASN probeCC={selectedCC} domainName={selectedDomainName} probeASN={selectedASN} />}
              </Box>
              <Box width={1}>
                {selectedDomainName !== null && <ChartDomainBlockingByASN probeCC={selectedCC} domainName={selectedDomainName} onClick={onSelectedASN} />}
              </Box>
            </Flex>
          </Box>
        </Flex>
      </Box>
    </Flex >
  )

}

const App = () => {
  return (
    <ThemeProvider theme={theme}>
      <GlobalStyle />
      <Container>
        <DataViz />
      </Container>
    </ThemeProvider>
  );
};

export default App;
