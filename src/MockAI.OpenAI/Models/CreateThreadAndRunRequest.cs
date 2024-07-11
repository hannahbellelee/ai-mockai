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
    public partial class CreateThreadAndRunRequest : IEquatable<CreateThreadAndRunRequest>
    { 
        /// <summary>
        /// The ID of the [assistant](/docs/api-reference/assistants) to use to execute this run.
        /// </summary>
        /// <value>The ID of the [assistant](/docs/api-reference/assistants) to use to execute this run.</value>
        [Required]

        [DataMember(Name="assistant_id")]
        public string AssistantId { get; set; }

        /// <summary>
        /// Gets or Sets Thread
        /// </summary>

        [DataMember(Name="thread")]
        public CreateThreadRequest Thread { get; set; }

        /// <summary>
        /// The ID of the [Model](/docs/api-reference/models) to be used to execute this run. If a value is provided here, it will override the model associated with the assistant. If not, the model associated with the assistant will be used.
        /// </summary>
        /// <value>The ID of the [Model](/docs/api-reference/models) to be used to execute this run. If a value is provided here, it will override the model associated with the assistant. If not, the model associated with the assistant will be used.</value>

        [DataMember(Name="model")]
        public AnyOfCreateThreadAndRunRequestModel Model { get; set; }

        /// <summary>
        /// Override the default system message of the assistant. This is useful for modifying the behavior on a per-run basis.
        /// </summary>
        /// <value>Override the default system message of the assistant. This is useful for modifying the behavior on a per-run basis.</value>

        [DataMember(Name="instructions")]
        public string Instructions { get; set; }

        /// <summary>
        /// Override the tools the assistant can use for this run. This is useful for modifying the behavior on a per-run basis.
        /// </summary>
        /// <value>Override the tools the assistant can use for this run. This is useful for modifying the behavior on a per-run basis.</value>

        [DataMember(Name="tools")]
        public List<OneOfCreateThreadAndRunRequestToolsItems> Tools { get; set; }

        /// <summary>
        /// Gets or Sets ToolResources
        /// </summary>

        [DataMember(Name="tool_resources")]
        public CreateThreadAndRunRequestToolResources ToolResources { get; set; }

        /// <summary>
        /// Set of 16 key-value pairs that can be attached to an object. This can be useful for storing additional information about the object in a structured format. Keys can be a maximum of 64 characters long and values can be a maxium of 512 characters long. 
        /// </summary>
        /// <value>Set of 16 key-value pairs that can be attached to an object. This can be useful for storing additional information about the object in a structured format. Keys can be a maximum of 64 characters long and values can be a maxium of 512 characters long. </value>

        [DataMember(Name="metadata")]
        public Object Metadata { get; set; }

        /// <summary>
        /// What sampling temperature to use, between 0 and 2. Higher values like 0.8 will make the output more random, while lower values like 0.2 will make it more focused and deterministic. 
        /// </summary>
        /// <value>What sampling temperature to use, between 0 and 2. Higher values like 0.8 will make the output more random, while lower values like 0.2 will make it more focused and deterministic. </value>

        [Range(0, 2)]
        [DataMember(Name="temperature")]
        public decimal? Temperature { get; set; }

        /// <summary>
        /// An alternative to sampling with temperature, called nucleus sampling, where the model considers the results of the tokens with top_p probability mass. So 0.1 means only the tokens comprising the top 10% probability mass are considered.  We generally recommend altering this or temperature but not both. 
        /// </summary>
        /// <value>An alternative to sampling with temperature, called nucleus sampling, where the model considers the results of the tokens with top_p probability mass. So 0.1 means only the tokens comprising the top 10% probability mass are considered.  We generally recommend altering this or temperature but not both. </value>

        [Range(0, 1)]
        [DataMember(Name="top_p")]
        public decimal? TopP { get; set; }

        /// <summary>
        /// If &#x60;true&#x60;, returns a stream of events that happen during the Run as server-sent events, terminating when the Run enters a terminal state with a &#x60;data: [DONE]&#x60; message. 
        /// </summary>
        /// <value>If &#x60;true&#x60;, returns a stream of events that happen during the Run as server-sent events, terminating when the Run enters a terminal state with a &#x60;data: [DONE]&#x60; message. </value>

        [DataMember(Name="stream")]
        public bool? Stream { get; set; }

        /// <summary>
        /// The maximum number of prompt tokens that may be used over the course of the run. The run will make a best effort to use only the number of prompt tokens specified, across multiple turns of the run. If the run exceeds the number of prompt tokens specified, the run will end with status &#x60;incomplete&#x60;. See &#x60;incomplete_details&#x60; for more info. 
        /// </summary>
        /// <value>The maximum number of prompt tokens that may be used over the course of the run. The run will make a best effort to use only the number of prompt tokens specified, across multiple turns of the run. If the run exceeds the number of prompt tokens specified, the run will end with status &#x60;incomplete&#x60;. See &#x60;incomplete_details&#x60; for more info. </value>

        [DataMember(Name="max_prompt_tokens")]
        public int? MaxPromptTokens { get; set; }

        /// <summary>
        /// The maximum number of completion tokens that may be used over the course of the run. The run will make a best effort to use only the number of completion tokens specified, across multiple turns of the run. If the run exceeds the number of completion tokens specified, the run will end with status &#x60;incomplete&#x60;. See &#x60;incomplete_details&#x60; for more info. 
        /// </summary>
        /// <value>The maximum number of completion tokens that may be used over the course of the run. The run will make a best effort to use only the number of completion tokens specified, across multiple turns of the run. If the run exceeds the number of completion tokens specified, the run will end with status &#x60;incomplete&#x60;. See &#x60;incomplete_details&#x60; for more info. </value>

        [DataMember(Name="max_completion_tokens")]
        public int? MaxCompletionTokens { get; set; }

        /// <summary>
        /// Gets or Sets TruncationStrategy
        /// </summary>

        [DataMember(Name="truncation_strategy")]
        public TruncationObject TruncationStrategy { get; set; }

        /// <summary>
        /// Gets or Sets ToolChoice
        /// </summary>

        [DataMember(Name="tool_choice")]
        public AssistantsApiToolChoiceOption ToolChoice { get; set; }

        /// <summary>
        /// Gets or Sets ParallelToolCalls
        /// </summary>

        [DataMember(Name="parallel_tool_calls")]
        public bool? ParallelToolCalls { get; set; }

        /// <summary>
        /// Gets or Sets ResponseFormat
        /// </summary>

        [DataMember(Name="response_format")]
        public AssistantsApiResponseFormatOption ResponseFormat { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class CreateThreadAndRunRequest {\n");
            sb.Append("  AssistantId: ").Append(AssistantId).Append("\n");
            sb.Append("  Thread: ").Append(Thread).Append("\n");
            sb.Append("  Model: ").Append(Model).Append("\n");
            sb.Append("  Instructions: ").Append(Instructions).Append("\n");
            sb.Append("  Tools: ").Append(Tools).Append("\n");
            sb.Append("  ToolResources: ").Append(ToolResources).Append("\n");
            sb.Append("  Metadata: ").Append(Metadata).Append("\n");
            sb.Append("  Temperature: ").Append(Temperature).Append("\n");
            sb.Append("  TopP: ").Append(TopP).Append("\n");
            sb.Append("  Stream: ").Append(Stream).Append("\n");
            sb.Append("  MaxPromptTokens: ").Append(MaxPromptTokens).Append("\n");
            sb.Append("  MaxCompletionTokens: ").Append(MaxCompletionTokens).Append("\n");
            sb.Append("  TruncationStrategy: ").Append(TruncationStrategy).Append("\n");
            sb.Append("  ToolChoice: ").Append(ToolChoice).Append("\n");
            sb.Append("  ParallelToolCalls: ").Append(ParallelToolCalls).Append("\n");
            sb.Append("  ResponseFormat: ").Append(ResponseFormat).Append("\n");
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
            return obj.GetType() == GetType() && Equals((CreateThreadAndRunRequest)obj);
        }

        /// <summary>
        /// Returns true if CreateThreadAndRunRequest instances are equal
        /// </summary>
        /// <param name="other">Instance of CreateThreadAndRunRequest to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(CreateThreadAndRunRequest other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return 
                (
                    AssistantId == other.AssistantId ||
                    AssistantId != null &&
                    AssistantId.Equals(other.AssistantId)
                ) && 
                (
                    Thread == other.Thread ||
                    Thread != null &&
                    Thread.Equals(other.Thread)
                ) && 
                (
                    Model == other.Model ||
                    Model != null &&
                    Model.Equals(other.Model)
                ) && 
                (
                    Instructions == other.Instructions ||
                    Instructions != null &&
                    Instructions.Equals(other.Instructions)
                ) && 
                (
                    Tools == other.Tools ||
                    Tools != null &&
                    Tools.SequenceEqual(other.Tools)
                ) && 
                (
                    ToolResources == other.ToolResources ||
                    ToolResources != null &&
                    ToolResources.Equals(other.ToolResources)
                ) && 
                (
                    Metadata == other.Metadata ||
                    Metadata != null &&
                    Metadata.Equals(other.Metadata)
                ) && 
                (
                    Temperature == other.Temperature ||
                    Temperature != null &&
                    Temperature.Equals(other.Temperature)
                ) && 
                (
                    TopP == other.TopP ||
                    TopP != null &&
                    TopP.Equals(other.TopP)
                ) && 
                (
                    Stream == other.Stream ||
                    Stream != null &&
                    Stream.Equals(other.Stream)
                ) && 
                (
                    MaxPromptTokens == other.MaxPromptTokens ||
                    MaxPromptTokens != null &&
                    MaxPromptTokens.Equals(other.MaxPromptTokens)
                ) && 
                (
                    MaxCompletionTokens == other.MaxCompletionTokens ||
                    MaxCompletionTokens != null &&
                    MaxCompletionTokens.Equals(other.MaxCompletionTokens)
                ) && 
                (
                    TruncationStrategy == other.TruncationStrategy ||
                    TruncationStrategy != null &&
                    TruncationStrategy.Equals(other.TruncationStrategy)
                ) && 
                (
                    ToolChoice == other.ToolChoice ||
                    ToolChoice != null &&
                    ToolChoice.Equals(other.ToolChoice)
                ) && 
                (
                    ParallelToolCalls == other.ParallelToolCalls ||
                    ParallelToolCalls != null &&
                    ParallelToolCalls.Equals(other.ParallelToolCalls)
                ) && 
                (
                    ResponseFormat == other.ResponseFormat ||
                    ResponseFormat != null &&
                    ResponseFormat.Equals(other.ResponseFormat)
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
                    if (AssistantId != null)
                    hashCode = hashCode * 59 + AssistantId.GetHashCode();
                    if (Thread != null)
                    hashCode = hashCode * 59 + Thread.GetHashCode();
                    if (Model != null)
                    hashCode = hashCode * 59 + Model.GetHashCode();
                    if (Instructions != null)
                    hashCode = hashCode * 59 + Instructions.GetHashCode();
                    if (Tools != null)
                    hashCode = hashCode * 59 + Tools.GetHashCode();
                    if (ToolResources != null)
                    hashCode = hashCode * 59 + ToolResources.GetHashCode();
                    if (Metadata != null)
                    hashCode = hashCode * 59 + Metadata.GetHashCode();
                    if (Temperature != null)
                    hashCode = hashCode * 59 + Temperature.GetHashCode();
                    if (TopP != null)
                    hashCode = hashCode * 59 + TopP.GetHashCode();
                    if (Stream != null)
                    hashCode = hashCode * 59 + Stream.GetHashCode();
                    if (MaxPromptTokens != null)
                    hashCode = hashCode * 59 + MaxPromptTokens.GetHashCode();
                    if (MaxCompletionTokens != null)
                    hashCode = hashCode * 59 + MaxCompletionTokens.GetHashCode();
                    if (TruncationStrategy != null)
                    hashCode = hashCode * 59 + TruncationStrategy.GetHashCode();
                    if (ToolChoice != null)
                    hashCode = hashCode * 59 + ToolChoice.GetHashCode();
                    if (ParallelToolCalls != null)
                    hashCode = hashCode * 59 + ParallelToolCalls.GetHashCode();
                    if (ResponseFormat != null)
                    hashCode = hashCode * 59 + ResponseFormat.GetHashCode();
                return hashCode;
            }
        }

        #region Operators
        #pragma warning disable 1591

        public static bool operator ==(CreateThreadAndRunRequest left, CreateThreadAndRunRequest right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(CreateThreadAndRunRequest left, CreateThreadAndRunRequest right)
        {
            return !Equals(left, right);
        }

        #pragma warning restore 1591
        #endregion Operators
    }
}
