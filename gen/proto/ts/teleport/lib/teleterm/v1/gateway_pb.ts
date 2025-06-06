/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter eslint_disable,add_pb_suffix,server_grpc1,ts_nocheck
// @generated from protobuf file "teleport/lib/teleterm/v1/gateway.proto" (package "teleport.lib.teleterm.v1", syntax proto3)
// tslint:disable
// @ts-nocheck
//
//
// Teleport
// Copyright (C) 2023  Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
import type { BinaryWriteOptions } from "@protobuf-ts/runtime";
import type { IBinaryWriter } from "@protobuf-ts/runtime";
import { WireType } from "@protobuf-ts/runtime";
import type { BinaryReadOptions } from "@protobuf-ts/runtime";
import type { IBinaryReader } from "@protobuf-ts/runtime";
import { UnknownFieldHandler } from "@protobuf-ts/runtime";
import type { PartialMessage } from "@protobuf-ts/runtime";
import { reflectionMergePartial } from "@protobuf-ts/runtime";
import { MessageType } from "@protobuf-ts/runtime";
/**
 * Gateway is Teleterm's name for a connection to a resource like a database or a web app
 * established through our ALPN proxy.
 *
 * The term "gateway" is used to avoid using the term "proxy" itself which could be confusing as
 * "proxy" means a couple of different things depending on the context. But for Teleterm, a gateway
 * is always an ALPN proxy connection.
 *
 * See RFD 39 for more info on ALPN.
 *
 * @generated from protobuf message teleport.lib.teleterm.v1.Gateway
 */
export interface Gateway {
    /**
     * uri is the gateway uri
     *
     * @generated from protobuf field: string uri = 1;
     */
    uri: string;
    /**
     * target_name is the target resource name
     *
     * @generated from protobuf field: string target_name = 2;
     */
    targetName: string;
    /**
     * target_uri is the target uri
     *
     * @generated from protobuf field: string target_uri = 3;
     */
    targetUri: string;
    /**
     * target_user is the target user
     *
     * @generated from protobuf field: string target_user = 4;
     */
    targetUser: string;
    /**
     * local_address is the gateway address on localhost
     *
     * @generated from protobuf field: string local_address = 5;
     */
    localAddress: string;
    /**
     * local_port is the gateway address on localhost
     *
     * @generated from protobuf field: string local_port = 6;
     */
    localPort: string;
    /**
     * protocol is the protocol used by the gateway. For databases, it matches the type of the
     * database that the gateway targets. For apps, it's either "HTTP" or "TCP".
     *
     * @generated from protobuf field: string protocol = 7;
     */
    protocol: string;
    /**
     * target_subresource_name points at a subresource of the remote resource, for example a
     * database name on a database server or a target port of a multi-port TCP app.
     *
     * @generated from protobuf field: string target_subresource_name = 9;
     */
    targetSubresourceName: string;
    /**
     * gateway_cli_client represents a command that the user can execute to connect to the resource
     * through the gateway.
     *
     * Instead of generating those commands in in the frontend code, they are returned from the tsh
     * daemon. This means that the Database Access team can add support for a new protocol and
     * Connect will support it right away with no extra changes.
     *
     * @generated from protobuf field: teleport.lib.teleterm.v1.GatewayCLICommand gateway_cli_command = 10;
     */
    gatewayCliCommand?: GatewayCLICommand;
}
/**
 * GatewayCLICommand represents a command that the user can execute to connect to a gateway
 * resource. It is a combination of two different os/exec.Cmd structs, where path, args and env are
 * directly taken from one Cmd and the preview field is constructed from another Cmd.
 *
 * @generated from protobuf message teleport.lib.teleterm.v1.GatewayCLICommand
 */
export interface GatewayCLICommand {
    /**
     * path is the absolute path to the CLI client of a gateway if the client is
     * in PATH. Otherwise, the name of the program we were trying to find.
     *
     * @generated from protobuf field: string path = 1;
     */
    path: string;
    /**
     * args is a list containing the name of the program as the first element
     * and the actual args as the other elements
     *
     * @generated from protobuf field: repeated string args = 2;
     */
    args: string[];
    /**
     * env is a list of env vars that need to be set for the command
     * invocation. The elements of the list are in the format of NAME=value.
     *
     * @generated from protobuf field: repeated string env = 3;
     */
    env: string[];
    /**
     * preview is used to show the user what command will be executed before they decide to run it.
     * It can also be copied and then pasted into a terminal.
     * It's like os/exec.Cmd.String with two exceptions:
     *
     * 1) It is prepended with Cmd.Env.
     * 2) The command name is relative and not absolute.
     * 3) It is taken from a different Cmd than the other fields in this message. This Cmd uses a
     * special print format which makes the args suitable to be entered into a terminal, but not to
     * directly spawn a process.
     *
     * Should not be used to execute the command in the shell. Instead, use path, args, and env.
     *
     * @generated from protobuf field: string preview = 4;
     */
    preview: string;
}
// @generated message type with reflection information, may provide speed optimized methods
class Gateway$Type extends MessageType<Gateway> {
    constructor() {
        super("teleport.lib.teleterm.v1.Gateway", [
            { no: 1, name: "uri", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 2, name: "target_name", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 3, name: "target_uri", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 4, name: "target_user", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 5, name: "local_address", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 6, name: "local_port", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 7, name: "protocol", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 9, name: "target_subresource_name", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 10, name: "gateway_cli_command", kind: "message", T: () => GatewayCLICommand }
        ]);
    }
    create(value?: PartialMessage<Gateway>): Gateway {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.uri = "";
        message.targetName = "";
        message.targetUri = "";
        message.targetUser = "";
        message.localAddress = "";
        message.localPort = "";
        message.protocol = "";
        message.targetSubresourceName = "";
        if (value !== undefined)
            reflectionMergePartial<Gateway>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: Gateway): Gateway {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* string uri */ 1:
                    message.uri = reader.string();
                    break;
                case /* string target_name */ 2:
                    message.targetName = reader.string();
                    break;
                case /* string target_uri */ 3:
                    message.targetUri = reader.string();
                    break;
                case /* string target_user */ 4:
                    message.targetUser = reader.string();
                    break;
                case /* string local_address */ 5:
                    message.localAddress = reader.string();
                    break;
                case /* string local_port */ 6:
                    message.localPort = reader.string();
                    break;
                case /* string protocol */ 7:
                    message.protocol = reader.string();
                    break;
                case /* string target_subresource_name */ 9:
                    message.targetSubresourceName = reader.string();
                    break;
                case /* teleport.lib.teleterm.v1.GatewayCLICommand gateway_cli_command */ 10:
                    message.gatewayCliCommand = GatewayCLICommand.internalBinaryRead(reader, reader.uint32(), options, message.gatewayCliCommand);
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: Gateway, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* string uri = 1; */
        if (message.uri !== "")
            writer.tag(1, WireType.LengthDelimited).string(message.uri);
        /* string target_name = 2; */
        if (message.targetName !== "")
            writer.tag(2, WireType.LengthDelimited).string(message.targetName);
        /* string target_uri = 3; */
        if (message.targetUri !== "")
            writer.tag(3, WireType.LengthDelimited).string(message.targetUri);
        /* string target_user = 4; */
        if (message.targetUser !== "")
            writer.tag(4, WireType.LengthDelimited).string(message.targetUser);
        /* string local_address = 5; */
        if (message.localAddress !== "")
            writer.tag(5, WireType.LengthDelimited).string(message.localAddress);
        /* string local_port = 6; */
        if (message.localPort !== "")
            writer.tag(6, WireType.LengthDelimited).string(message.localPort);
        /* string protocol = 7; */
        if (message.protocol !== "")
            writer.tag(7, WireType.LengthDelimited).string(message.protocol);
        /* string target_subresource_name = 9; */
        if (message.targetSubresourceName !== "")
            writer.tag(9, WireType.LengthDelimited).string(message.targetSubresourceName);
        /* teleport.lib.teleterm.v1.GatewayCLICommand gateway_cli_command = 10; */
        if (message.gatewayCliCommand)
            GatewayCLICommand.internalBinaryWrite(message.gatewayCliCommand, writer.tag(10, WireType.LengthDelimited).fork(), options).join();
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.Gateway
 */
export const Gateway = new Gateway$Type();
// @generated message type with reflection information, may provide speed optimized methods
class GatewayCLICommand$Type extends MessageType<GatewayCLICommand> {
    constructor() {
        super("teleport.lib.teleterm.v1.GatewayCLICommand", [
            { no: 1, name: "path", kind: "scalar", T: 9 /*ScalarType.STRING*/ },
            { no: 2, name: "args", kind: "scalar", repeat: 2 /*RepeatType.UNPACKED*/, T: 9 /*ScalarType.STRING*/ },
            { no: 3, name: "env", kind: "scalar", repeat: 2 /*RepeatType.UNPACKED*/, T: 9 /*ScalarType.STRING*/ },
            { no: 4, name: "preview", kind: "scalar", T: 9 /*ScalarType.STRING*/ }
        ]);
    }
    create(value?: PartialMessage<GatewayCLICommand>): GatewayCLICommand {
        const message = globalThis.Object.create((this.messagePrototype!));
        message.path = "";
        message.args = [];
        message.env = [];
        message.preview = "";
        if (value !== undefined)
            reflectionMergePartial<GatewayCLICommand>(this, message, value);
        return message;
    }
    internalBinaryRead(reader: IBinaryReader, length: number, options: BinaryReadOptions, target?: GatewayCLICommand): GatewayCLICommand {
        let message = target ?? this.create(), end = reader.pos + length;
        while (reader.pos < end) {
            let [fieldNo, wireType] = reader.tag();
            switch (fieldNo) {
                case /* string path */ 1:
                    message.path = reader.string();
                    break;
                case /* repeated string args */ 2:
                    message.args.push(reader.string());
                    break;
                case /* repeated string env */ 3:
                    message.env.push(reader.string());
                    break;
                case /* string preview */ 4:
                    message.preview = reader.string();
                    break;
                default:
                    let u = options.readUnknownField;
                    if (u === "throw")
                        throw new globalThis.Error(`Unknown field ${fieldNo} (wire type ${wireType}) for ${this.typeName}`);
                    let d = reader.skip(wireType);
                    if (u !== false)
                        (u === true ? UnknownFieldHandler.onRead : u)(this.typeName, message, fieldNo, wireType, d);
            }
        }
        return message;
    }
    internalBinaryWrite(message: GatewayCLICommand, writer: IBinaryWriter, options: BinaryWriteOptions): IBinaryWriter {
        /* string path = 1; */
        if (message.path !== "")
            writer.tag(1, WireType.LengthDelimited).string(message.path);
        /* repeated string args = 2; */
        for (let i = 0; i < message.args.length; i++)
            writer.tag(2, WireType.LengthDelimited).string(message.args[i]);
        /* repeated string env = 3; */
        for (let i = 0; i < message.env.length; i++)
            writer.tag(3, WireType.LengthDelimited).string(message.env[i]);
        /* string preview = 4; */
        if (message.preview !== "")
            writer.tag(4, WireType.LengthDelimited).string(message.preview);
        let u = options.writeUnknownFields;
        if (u !== false)
            (u == true ? UnknownFieldHandler.onWrite : u)(this.typeName, message, writer);
        return writer;
    }
}
/**
 * @generated MessageType for protobuf message teleport.lib.teleterm.v1.GatewayCLICommand
 */
export const GatewayCLICommand = new GatewayCLICommand$Type();
