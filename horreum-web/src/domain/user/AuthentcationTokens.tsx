import {useContext, useEffect, useState} from "react"
import {
    Button,
    ClipboardCopy,
    DatePicker,
    Form,
    FormGroup,
    Label,
    Modal,
    TextInput,
    Tooltip,
    yyyyMMddFormat,
} from "@patternfly/react-core"

import {HorreumAuthenticationToken, userApi} from "../../api";
import {AppContext} from "../../context/appContext";
import {AppContextType} from "../../context/@types/appContextTypes";
import {ActionsColumn, Table, Tbody, Td, Th, Thead, Tr} from "@patternfly/react-table";

export default function AuthenticationTokens() {
    const {alerting} = useContext(AppContext) as AppContextType;

    const daysTo = (other: Date) => Math.ceil((other.getTime() - Date.now()) / (24 * 3600 * 1000))
    const defaultExpiration = () => yyyyMMddFormat(new Date(Date.now() + 400 * 24 * 3600 * 1000)) // default 400 days

    const refreshTokens = () =>
        userApi.authenticationTokens().then(
            users => setAuthenticationTokens(users),
            error => alerting.dispatchError(error, "FETCH_AUTHENTICATION_TOKEN", "Failed to fetch authentication tokens for user")
        )

    const [authenticationTokens, setAuthenticationTokens] = useState<HorreumAuthenticationToken[]>([])
    const [createNewToken, setCreateNewToken] = useState(false)
    const [newAuthenticationTokenValue, setNewAuthenticationTokenValue] = useState<string>()

    const [newTokenName, setNewTokenName] = useState<string>()
    const [newTokenExpiration, setNewTokenExpiration] = useState<string>(defaultExpiration)

    const rangeValidator = (date: Date) => {
        const days = daysTo(date);
        if (days < 0) {
            return 'Date is before the allowable range';
        } else if (days > 1000) { // max lifetime of the token
            return 'Date is after the allowable range';
        }
        return '';
    };

    const resetNewToken = () => {
        setCreateNewToken(false)
        setNewTokenName(undefined)
        setNewTokenExpiration(defaultExpiration())
    }

    const tokenStatus = (token: HorreumAuthenticationToken) => {
        if (token.isRevoked) {
            return <Label color="red">Revoked</Label>
        } else if (token.isExpired) {
            return <Label color="grey">Expired</Label>
        } else if (token.dateExpired) {
            const d = daysTo(token.dateExpired)
            if (d < 1) {
                return <Label color="orange">Expires TODAY</Label>
            } else if (d < 7) {
                return <Label color="gold">Expires in less than a week</Label>
            } else if (d < 30) {
                return <Label color="green">Expires in less than a month</Label>
            }
        }
        return <></>
    }

    const tokenTooltip = (token: HorreumAuthenticationToken) => {
        if (token.isExpired) {
            return "Token has expired"
        } else if (token.dateExpired) {
            const d = daysTo(token.dateExpired)
            if (d == 0) {
                return "Token expires TODAY!"
            } else {
                return `Token expires in ${d} days`
            }
        }
        return ""
    }

    useEffect(() => {
        void refreshTokens();
    }, [])

    return (
        <>
            <Table aria-label="AuthenticationTokens" isStickyHeader borders={false}>
                <Thead>
                    <Tr>
                        <Th label="name">Token Name</Th>
                        <Th label="status">Status</Th>
                        <Th label="expiration">Expiration</Th>
                    </Tr>
                </Thead>
                <Tbody>
                    {authenticationTokens.filter(token => daysTo(token.dateExpired ?? new Date()) >= -30).map((token, i) => ( // filter tokens that expired over 30 days
                        <Tr key={"token-" + i}>
                            <Td dataLabel="name">{token.name}</Td>
                            <Td dataLabel="status">{tokenStatus(token)}</Td>
                            <Td dataLabel="expiration">
                                <Tooltip content={tokenTooltip(token)}><span
                                    id={"authentication-token-expired-" + i}>{token.dateExpired?.toLocaleDateString()}</span>
                                </Tooltip>
                            </Td>
                            <Td isActionCell>
                                <ActionsColumn items={[
                                    {
                                        title: 'Revoke',
                                        onClick: () => {
                                            if (token.id && confirm(`Are you sure you want to revoke token '${token.name}'?`)) {
                                                userApi.revokeAuthenticationToken(token.id).then(
                                                    _ => void refreshTokens(),
                                                    error => alerting.dispatchError(error, "REVOKE_TOKEN", "Failed to revoke token")
                                                )
                                            }
                                        }
                                    }
                                ]}
                                />
                            </Td>
                        </Tr>
                    ))}
                </Tbody>
            </Table>
            <Button onClick={() => setCreateNewToken(true)}>New token</Button>

            <Modal
                title="Create new authentication token"
                variant="small"
                isOpen={createNewToken}
                onClose={resetNewToken}
                actions={[
                    <Button
                        onClick={() => {
                            userApi.newAuthenticationToken({
                                name: newTokenName,
                                expiration: daysTo(new Date(`${newTokenExpiration}`))
                            })
                                .then((tokenValue) => {
                                    setNewAuthenticationTokenValue(tokenValue)
                                    void alerting.dispatchInfo(
                                        "TOKEN_CREATED",
                                        "Authentication token created",
                                        "Authentication token was successfully created",
                                        3000
                                    )
                                })
                                .catch(error => alerting.dispatchError(error, "TOKEN_NOT_CREATED", "Failed to create new authentication token"))
                                .finally(() => setCreateNewToken(false))
                                .then(() => void refreshTokens())
                        }}
                    >
                        Create
                    </Button>,
                    <Button variant="secondary" onClick={resetNewToken}>Cancel</Button>,
                ]}
            >
                <Form isHorizontal>
                    <FormGroup isRequired label="Token Name" fieldId="newTokenName">
                        <TextInput
                            isRequired
                            value={newTokenName}
                            onChange={(_event, val) => setNewTokenName(val)}
                        />
                    </FormGroup>
                    <FormGroup label="Expiration date" fieldId="newTokenExpiration">
                        <DatePicker value={newTokenExpiration}
                                    onChange={(_, date) => setNewTokenExpiration(date)}
                                    validators={[rangeValidator]}/>
                    </FormGroup>
                </Form>
            </Modal>
            <Modal
                isOpen={newAuthenticationTokenValue != undefined}
                title={`New token: ${newTokenName}`}
                aria-label="New authentication token"
                variant="small"
                onClose={() => setNewAuthenticationTokenValue(undefined)}>
                <ClipboardCopy isReadOnly>{newAuthenticationTokenValue}</ClipboardCopy>
            </Modal>
        </>
    )
}
