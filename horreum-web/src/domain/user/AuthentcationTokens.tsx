import {useContext, useEffect, useState} from "react"
import {
    Button,
    ClipboardCopy,
    DatePicker,
    Form,
    FormGroup,
    HelperText,
    HelperTextItem,
    Label,
    Modal,
    NumberInput,
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

    const [authenticationTokens, setAuthenticationTokens] = useState<HorreumAuthenticationToken[]>([])
    const refreshTokens = () => userApi.authenticationTokens().then(
        users => setAuthenticationTokens(users),
        error => alerting.dispatchError(error, "FETCH_AUTHENTICATION_TOKEN", "Failed to fetch authentication tokens for user")
    )

    const [createNewToken, setCreateNewToken] = useState(false)
    const [newTokenName, setNewTokenName] = useState<string>()
    const [newTokenExpiration, setNewTokenExpiration] = useState<string>(defaultExpiration)
    const [newAuthenticationTokenValue, setNewAuthenticationTokenValue] = useState<string>()

    const [renewTokenId, setRenewTokenId] = useState<number>()
    const [renewTokenExpiration, setRenewTokenExpiration] = useState<number>(90)

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
        } else if (!token.lastAccess) {
            return <Label color="cyan">Never used</Label>
        } else if (token.dateExpired) {
            const d = daysTo(token.dateExpired)
            if (d < 1) {
                return <Label color="orange">Expires TODAY</Label>
            } else if (d < 2) {
                return <Label color="orange">Expires TOMORROW</Label>
            }
            if (d < 7) {
                return <Label color="gold">Expires in less than a week</Label>
            } else if (d < 30) {
                return <Label color="green">Expires in less than a month</Label>
            }
        }
        return <Label color="green">Valid</Label>
    }

    const tokenCreatedTooltip = (token: HorreumAuthenticationToken) => {
        if (!token.dateCreated) {
            return ""
        } else {
            const d = -daysTo(token.dateCreated)
            if (d == 0) {
                return "Token was created today"
            } else {
                return `Token was created ${d} days ago`
            }
        }
    }

    const tokenAccessTooltip = (token: HorreumAuthenticationToken) => {
        if (!token.lastAccess) {
            return "Token has never been used"
        } else {
            const d = -daysTo(token.lastAccess)
            if (d == 0) {
                return "Token was last used today"
            } else {
                return `Token was last used ${d} days ago`
            }
        }
    }

    const tokenExpirationTooltip = (token: HorreumAuthenticationToken) => {
        if (token.isRevoked) {
            return "Token has been revoked"
        } else if (token.isExpired) {
            return "Token has expired"
        } else if (token.dateExpired) {
            const d = daysTo(token.dateExpired)
            if (d == 0) {
                return "Token expires TODAY!"
            } else {
                return `Token expires in ${d} days`
            }
        }
    }

    useEffect(() => {
        void refreshTokens();
    }, [])

    return (
        <>
            <Table aria-label="AuthenticationTokens" isStickyHeader borders={false}>
                <Thead>
                    <Tr>
                        <Th label="name" width={50}>Token Name</Th>
                        <Th label="create">Creation date</Th>
                        <Th label="access">Last usage</Th>
                        <Th label="expiration">Expiration date</Th>
                        <Th label="status">Status</Th>
                    </Tr>
                </Thead>
                <Tbody>
                    {authenticationTokens.map((token, i) => (
                        <Tr key={`token-${i}`}>
                            <Td dataLabel="name">{token.name}</Td>
                            <Td dataLabel="access">
                                <Tooltip content={tokenCreatedTooltip(token)}>
                                    <span>{token.dateCreated?.toLocaleDateString() || "undefined"}</span>
                                </Tooltip>
                            </Td>
                            <Td dataLabel="access">
                                <Tooltip content={tokenAccessTooltip(token)} isVisible={token.lastAccess != null}>
                                    <span>{token.lastAccess?.toLocaleDateString()}</span>
                                </Tooltip>
                            </Td>
                            <Td dataLabel="expiration">
                                <Tooltip content={tokenExpirationTooltip(token)}>
                                    <span>{token.dateExpired?.toLocaleDateString() || "undefined"}</span>
                                </Tooltip>
                            </Td>
                            <Td dataLabel="status">{tokenStatus(token)}</Td>
                            <Td isActionCell>
                                <ActionsColumn items={token.isRevoked ? [] : [
                                    {
                                        title: 'Renew',
                                        isDisabled: !(token.dateExpired && daysTo(token.dateExpired) < 7), // only allow to renew in last 7 days
                                        onClick: () => {
                                            setRenewTokenExpiration(90)
                                            setRenewTokenId(token.id)
                                        }
                                    },
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
                                    void alerting.dispatchInfo("TOKEN_CREATED", "Authentication token created", "Authentication token was successfully created", 3000)
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
                footer={
                    <HelperText>
                        <HelperTextItem variant="warning" hasIcon>This is the only time you'll be able to see the
                            token</HelperTextItem>
                    </HelperText>
                }
                aria-label="new-authentication-token"
                variant="small"
                onClose={() => setNewAuthenticationTokenValue(undefined)}>
                <ClipboardCopy isReadOnly>{newAuthenticationTokenValue}</ClipboardCopy>
            </Modal>
            <Modal
                isOpen={renewTokenId != undefined}
                title={`Renew token`}
                aria-label="renew-authentication-token"
                variant="small"
                onClose={() => setNewAuthenticationTokenValue(undefined)}
                actions={[
                    <Button
                        onClick={() => {
                            if (renewTokenId) {
                                userApi.renewAuthenticationToken(renewTokenId, renewTokenExpiration)
                                    .then(() => void alerting.dispatchInfo("TOKEN_RENEWED", "Authentication token renewed", "Authentication token was successfully renewed", 3000))
                                    .catch(error => alerting.dispatchError(error, "TOKEN_NOT_RENEWED", "Failed to renew authentication token"))
                                    .finally(() => setRenewTokenId(undefined))
                                    .then(() => void refreshTokens())
                            }
                        }}
                    >
                        Renew
                    </Button>,
                    <Button variant="secondary" onClick={() => setRenewTokenId(undefined)}>Cancel</Button>,
                ]}>
                <Form isHorizontal>
                    <FormGroup isRequired label="Days to expiration" fieldId="renew-authentication-token-expiration">
                        <NumberInput
                            value={renewTokenExpiration}
                            min={0}
                            max={100}
                            onMinus={() => setRenewTokenExpiration(renewTokenExpiration - 1)}
                            onPlus={() => setRenewTokenExpiration(renewTokenExpiration + 1)}
                            onChange={(event) => {
                                const value = (event.target as HTMLInputElement).value;
                                setRenewTokenExpiration(value === '' ? 0 : +value);
                            }}
                        />
                    </FormGroup>
                </Form>
            </Modal>
        </>
    )
}
