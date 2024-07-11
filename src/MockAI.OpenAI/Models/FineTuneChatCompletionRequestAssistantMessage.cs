/*
 * OpenAI API
 *
 * The OpenAI REST API. Please see https://platform.openai.com/docs/api-reference for more details.
 *
 * OpenAPI spec version: 2.1.0
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */
using System;
using System.Linq;
using System.IO;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace IO.Swagger.Models
{
    /// <summary>
    /// 
    /// </summary>
    [DataContract]
    public partial class FineTuneChatCompletionRequestAssistantMessage : IEquatable<FineTuneChatCompletionRequestAssistantMessage>, OneOfFinetuneChatRequestInputMessagesItems 
    { 
        /// <summary>
        /// Controls whether the assistant message is trained against (0 or 1)
        /// </summary>
        /// <value>Controls whether the assistant message is trained against (0 or 1)</value>
        [JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public enum WeightEnum
        {
            /// <summary>
            /// Enum NUMBER_0 for 0
            /// </summary>
            [EnumMember(Value = "0")]
            NUMBER_0 = 0,
            /// <summary>
            /// Enum NUMBER_1 for 1
            /// </summary>
            [EnumMember(Value = "1")]
            NUMBER_1 = 1        }

        /// <summary>
        /// Controls whether the assistant message is trained against (0 or 1)
        /// </summary>
        /// <value>Controls whether the assistant message is trained against (0 or 1)</value>

        [DataMember(Name="weight")]
        public WeightEnum? Weight { get; set; }

        /// <summary>
        /// The contents of the assistant message. Required unless &#x60;tool_calls&#x60; or &#x60;function_call&#x60; is specified. 
        /// </summary>
        /// <value>The contents of the assistant message. Required unless &#x60;tool_calls&#x60; or &#x60;function_call&#x60; is specified. </value>

        [DataMember(Name="content")]
        public string Content { get; set; }

        /// <summary>
        /// The role of the messages author, in this case `assistant`.
        /// </summary>
        /// <value>The role of the messages author, in this case `assistant`.</value>
        [JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public enum RoleEnum
        {
            /// <summary>
            /// Enum AssistantEnum for assistant
            /// </summary>
            [EnumMember(Value = "assistant")]
            AssistantEnum = 0        }

        /// <summary>
        /// The role of the messages author, in this case &#x60;assistant&#x60;.
        /// </summary>
        /// <value>The role of the messages author, in this case &#x60;assistant&#x60;.</value>
        [Required]

        [DataMember(Name="role")]
        public RoleEnum? Role { get; set; }

        /// <summary>
        /// An optional name for the participant. Provides the model information to differentiate between participants of the same role.
        /// </summary>
        /// <value>An optional name for the participant. Provides the model information to differentiate between participants of the same role.</value>

        [DataMember(Name="name")]
        public string Name { get; set; }

        /// <summary>
        /// Gets or Sets ToolCalls
        /// </summary>

        [DataMember(Name="tool_calls")]
        public ChatCompletionMessageToolCalls ToolCalls { get; set; }

        /// <summary>
        /// Gets or Sets FunctionCall
        /// </summary>

        [DataMember(Name="function_call")]
        public ChatCompletionRequestAssistantMessageFunctionCall FunctionCall { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class FineTuneChatCompletionRequestAssistantMessage {\n");
            sb.Append("  Weight: ").Append(Weight).Append("\n");
            sb.Append("  Content: ").Append(Content).Append("\n");
            sb.Append("  Role: ").Append(Role).Append("\n");
            sb.Append("  Name: ").Append(Name).Append("\n");
            sb.Append("  ToolCalls: ").Append(ToolCalls).Append("\n");
            sb.Append("  FunctionCall: ").Append(FunctionCall).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public string ToJson()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="obj">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj.GetType() == GetType() && Equals((FineTuneChatCompletionRequestAssistantMessage)obj);
        }

        /// <summary>
        /// Returns true if FineTuneChatCompletionRequestAssistantMessage instances are equal
        /// </summary>
        /// <param name="other">Instance of FineTuneChatCompletionRequestAssistantMessage to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(FineTuneChatCompletionRequestAssistantMessage other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return 
                (
                    Weight == other.Weight ||
                    Weight != null &&
                    Weight.Equals(other.Weight)
                ) && 
                (
                    Content == other.Content ||
                    Content != null &&
                    Content.Equals(other.Content)
                ) && 
                (
                    Role == other.Role ||
                    Role != null &&
                    Role.Equals(other.Role)
                ) && 
                (
                    Name == other.Name ||
                    Name != null &&
                    Name.Equals(other.Name)
                ) && 
                (
                    ToolCalls == other.ToolCalls ||
                    ToolCalls != null &&
                    ToolCalls.Equals(other.ToolCalls)
                ) && 
                (
                    FunctionCall == other.FunctionCall ||
                    FunctionCall != null &&
                    FunctionCall.Equals(other.FunctionCall)
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                var hashCode = 41;
                // Suitable nullity checks etc, of course :)
                    if (Weight != null)
                    hashCode = hashCode * 59 + Weight.GetHashCode();
                    if (Content != null)
                    hashCode = hashCode * 59 + Content.GetHashCode();
                    if (Role != null)
                    hashCode = hashCode * 59 + Role.GetHashCode();
                    if (Name != null)
                    hashCode = hashCode * 59 + Name.GetHashCode();
                    if (ToolCalls != null)
                    hashCode = hashCode * 59 + ToolCalls.GetHashCode();
                    if (FunctionCall != null)
                    hashCode = hashCode * 59 + FunctionCall.GetHashCode();
                return hashCode;
            }
        }

        #region Operators
        #pragma warning disable 1591

        public static bool operator ==(FineTuneChatCompletionRequestAssistantMessage left, FineTuneChatCompletionRequestAssistantMessage right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(FineTuneChatCompletionRequestAssistantMessage left, FineTuneChatCompletionRequestAssistantMessage right)
        {
            return !Equals(left, right);
        }

        #pragma warning restore 1591
        #endregion Operators
    }
}
